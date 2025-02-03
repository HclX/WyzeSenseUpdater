#!/usr/bin/env python3

import os
import sys
import logging
import errno
import time
import signal
import struct
import binascii
import argparse

SBL_CC2650_MAX_MEMREAD_WORDS = 63
SBL_CC2650_MAX_MEMREAD_BYTES = SBL_CC2650_MAX_MEMREAD_WORDS * 4
SBL_CC2650_ACCESS_WIDTH_32B = 1

MAX_PACK_SIZE = 0x3A

RSP_CODE_ACK = 0x00CC
RSP_CODE_NAK = 0x0033

CMD_PING             = 0x20
CMD_DOWNLOAD         = 0x21
CMD_GET_STATUS       = 0x23
CMD_SEND_DATA        = 0x24
CMD_RESET            = 0x25
CMD_SECTOR_ERASE     = 0x26
CMD_CRC32            = 0x27
CMD_GET_CHIP_ID      = 0x28
CMD_MEMORY_READ      = 0x2A
CMD_MEMORY_WRITE     = 0x2B
CMD_BANK_ERASE       = 0x2C
CMD_SET_CCFG         = 0x2D
CMD_AUTO_BAUD        = 0x55

FLASH_START_ADDR = 0x0
FLASH_SIZE = 0x20000
PAGE_SIZE = 0x1000
BL_CFG_OFFSET = 0xFD8

VENDOR_ID = 0x1a86
PRODUCT_ID = 0xe024

def hexify(data):
    if data and len(data):
        return ','.join(f'0x{x:02x}' for x in data) + f', len={len(data)}'
    else:
        return ''

def dongle_open(path):
    #return os.open(path, os.O_RDWR | os.O_NONBLOCK)
    return open(path, 'wb+')

def dongle_write(fd, data):
    # os.write(fd, data)
    return fd.write(data)

def dongle_read(fd, size):
    def handler(signum, frame):
        raise TimeoutError("File read timeout exceeded")

    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.alarm(5)
    try:
        data = fd.read(size)
        return data
    except TimeoutError:
        logging.error("Timeout occured!")
        raise
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def rawhid_read(fd):
    pkt = dongle_read(fd, 0x3f)
    logging.debug(f'[R]==>{hexify(pkt)}')
    pkt_len = pkt[0]
    pkt = pkt[1:1+pkt_len]
    return pkt

def rawhid_write(fd, payload):
    logging.debug(f'[W]==>{hexify(payload)}')
    dongle_write(fd, payload)

def dongle_checksum(cmd, data=b''):
    checksum = cmd
    for x in data:
        checksum += x
    return checksum & 0xFF

def dongle_ack(fd, success):
    rawhid_write(fd, bytes([0x00, 0xCC if success else 0x33]))

def dongle_cmd(fd, cmd, payload=b''):
    assert cmd <= 0xff, f'Invalid command: {cmd}'
    req = bytes([len(payload) + 3, dongle_checksum(cmd, payload), cmd])
    req += payload

    rawhid_write(fd, req)
    rsp = rawhid_read(fd)

    # Need at least two bytes for ACK code
    assert len(rsp) >= 2, f'Invalid response'

    ack = (rsp[0] << 8) | rsp[1]
    if ack != RSP_CODE_ACK:
        # NAK, return fail
        return False

    if len(rsp) == 2:
        # No payload, simply return success
        return True

    # When there is payload, it needs at least 3 bytes:
    #  2 bytes ack, 1 byte payload length, 1 byte payload checksum, payload bytes
    assert len(rsp) >= 4, f'Invalid payload'

    payload_len = rsp[2]
    # payload length includes the checksum and itself, so needs to be at least 2
    assert payload_len >= 2, f'Invalid payload length'

    payload_len -= 2
    payload_checksum = rsp[3]

    payload = rsp[4:]
    assert payload_len >= len(payload), f'Invalid payload length'

    payload_len -= len(payload)
    while payload_len > 0:
        rsp = rawhid_read(fd)
        if len(rsp) > payload_len:
            rsp = rsp[:payload_len]

        payload += rsp
        payload_len -= len(rsp)

    checksum = dongle_checksum(0, payload)
    if checksum != payload_checksum:
        logging.debug(f'Invalid checksum, received={payload_checksum:02X}, calculated={checksum:02X}')
        dongle_ack(fd, False)
        return None

    dongle_ack(fd, True)
    return payload


def cmd_auto_baud(fd):
    return dongle_cmd(fd, CMD_AUTO_BAUD)

def cmd_ping(fd):
    return dongle_cmd(fd, CMD_PING)

def cmd_chip_id(fd):
    rsp = dongle_cmd(fd, CMD_GET_CHIP_ID)
    assert len(rsp) == 4, f'Invalid response'
    return int.from_bytes(rsp, byteorder='big')

def cmd_status(fd):
    rsp = dongle_cmd(fd, CMD_GET_STATUS)
    assert len(rsp) == 1, f'Invalid response'
    return rsp[0]

def cmd_reset(fd):
    return dongle_cmd(fd, CMD_RESET)

def cmd_read_mem(fd, addr, size, progress_cb=lambda *args: None):
    assert addr & 0x03 == 0, f'Invalid address'
    assert size & 0x03 == 0, f'Invalid size'
    assert size > 0, f'Invalid size'

    data = b''
    while size > 0:
        progress_cb(f'Reading {addr:08X}...')
        chunk_size = size
        if chunk_size > SBL_CC2650_MAX_MEMREAD_BYTES:
            chunk_size = SBL_CC2650_MAX_MEMREAD_BYTES

        cmd_data = addr.to_bytes(4, byteorder='big') + bytes([1, chunk_size // 4])
        try:
            rsp = dongle_cmd(fd, CMD_MEMORY_READ, payload=cmd_data)
            if not rsp:
                break
        except TimeoutError:
            logging.error(f"Timeout while reading memory, {addr=:08X}, {chunk_size=:02X}")
            break

        assert len(rsp) == chunk_size, f'Invalid response'
        data += rsp
        size -= chunk_size
        addr += chunk_size

    progress_cb('', True)
    return data

def cmd_erase(fd, addr, size):
    assert addr % 0x1000 == 0, f'Invalid address, must be page aligned'
    assert size % 0x1000 == 0, f'Invalid size, must be page aligned'
    assert size > 0, f'Invalid erase size'

    while size > 0:
        logging.debug(f"Erasing page 0x{addr:08X}...")
        if not dongle_cmd(fd, CMD_SECTOR_ERASE, addr.to_bytes(4, byteorder='big')):
            logging.debug(f'Erasing failed')
            return False

        status = cmd_status(fd)
        if status != 0x40:
            logging.debug(f'Erasing failed, status={status:02x}')
            return False

        size -= 0x1000
        addr += 0x1000
    return True

def cmd_download(fd, addr, size):
    cmd_data = addr.to_bytes(4, byteorder='big') + size.to_bytes(4, byteorder='big')
    if not dongle_cmd(fd, CMD_DOWNLOAD, cmd_data):
        return False

    status = cmd_status(fd)
    if status != 0x40:
        return False

    return True

def cmd_send_data(fd, data):
    assert len(data) <= MAX_PACK_SIZE, f'Invalid data size'
    
    if not dongle_cmd(fd, CMD_SEND_DATA, data):
        return False

    status = cmd_status(fd)
    if status != 0x40:
        return False
    
    return True

def cmd_write_range(fd, addr, data, progress_cb=lambda x,y: None):
    bl_cfg_addr = FLASH_START_ADDR + FLASH_SIZE - PAGE_SIZE + BL_CFG_OFFSET
    assert addr < bl_cfg_addr, f'Invalid address'
    
    bl_cfg_idx = bl_cfg_addr - addr
    size = len(data)
    if bl_cfg_idx < size:
        assert data[bl_cfg_idx] == 0xC5, f'Invalid bootloader config byte:{data[bl_cfg_idx]:02X}'

    if not cmd_download(fd, addr, size):
        logging.error(f'Cmd Download failed...')
        return False

    offset = 0
    retry_count = 0
    while offset < size:
        progress_cb(f'Flashing {offset:08X}/{size:08X}...')

        chunk_size = size - offset
        if chunk_size > MAX_PACK_SIZE:
            chunk_size = MAX_PACK_SIZE

        if not cmd_send_data(fd, data[offset:offset + chunk_size]):
            retry_count += 1
            logging.warn(f'Sending data failed, retrying {retry_count}...')
            if retry_count > 3:
                logging.error(f'Max retry reached...')
                return False
            continue

        retry_count = 0
        offset += chunk_size
    progress_cb("", True)
    return True

def cmd_crc32(fd, addr, size):
    cmd_data = addr.to_bytes(4, byteorder='big') + size.to_bytes(4, byteorder='big') + b'\x00\x00\x00\x00'
    rsp = dongle_cmd(fd, CMD_CRC32, payload=cmd_data)
    assert len(rsp) ==4, f'Invalid response'
    return int.from_bytes(rsp, byteorder='big')

def show_progress(progress, done=False):
    sys.stdout.write(f'\r{progress}')
    sys.stdout.flush()

    if done:
        sys.stdout.write('\n')

def do_flash(fd, args):
    logging.info(f"Writing flash content from file {args.input}...")

    data = open(args.input, 'rb').read()
    if len(data) != FLASH_SIZE:
        logging.error(f'Invalid flash file size')
        return False

    bldr_cfg_idx = FLASH_SIZE - PAGE_SIZE + BL_CFG_OFFSET
    int.from_bytes(data[bldr_cfg_idx:bldr_cfg_idx+4], byteorder='big')
    if bldr_cfg != 0xC501FEC5:
        logging.error(f'Invalid bootloader config:{bldr_cfg:08X}')
        return False

    data_crc32 = binascii.crc32(data)
    logging.info(f"Firmware loaded from file, size=0x{len(data):08X}, CRC:0x{data_crc32:08X}")

    logging.info("Erasing flash...")
    if not cmd_erase(fd, FLASH_START_ADDR, len(data)):
        logging.error("Erasing flash failed")
        return False

    logging.info("Writing flash...")
    if not cmd_write_range(fd, FLASH_START_ADDR, data, progress_cb=show_progress):
        logging.error("Writing flash failed")
        return False

    chip_crc32 = cmd_crc32(fd, FLASH_START_ADDR, len(data))
    logging.info(f"Chip CRC:0x{chip_crc32:08X}")
    if chip_crc32 != data_crc32:
        logging.error("CRC doesn't match!")
        return False

    return True

def do_read(fd, args):
    logging.info(f"Reading content (address={args.address:08X}, count={args.count:08X}) to {args.output}...")

    rsp = cmd_read_mem(fd, args.address, args.count, progress_cb=show_progress)
    if not rsp:
        logging.info(f'Reading failed')
        return False

    if not args.ignore_error:
        assert len(rsp) == args.count, f'Invalid response'
        crc_chip = cmd_crc32(fd, args.address, args.count)
        crc_data = binascii.crc32(rsp)
        assert crc_chip == crc_data, f'Invalid CRC'

    with open(args.output, 'wb') as f:
        f.write(rsp)
    return True

def find_bridge_dev():
    # Path to the /dev directory for hidraw devices
    hidraw_base_path = "/dev/"
    hidraw_devices = [dev for dev in os.listdir(hidraw_base_path) if dev.startswith("hidraw")]

    pattern = f'{VENDOR_ID:04X}:{PRODUCT_ID:04X}'
    for hidraw in hidraw_devices:
        hidraw_path = os.path.join(hidraw_base_path, hidraw)
        # Get the sysfs path for the hidraw device
        sys_path = os.path.realpath(f"/sys/class/hidraw/{hidraw}")
        if pattern in sys_path:
            return hidraw_path
    return None

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Tool for device operations")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity level (-v for INFO, -vv for DEBUG)"
    )
    parser.add_argument("-d", "--device", type=str, default=find_bridge_dev(), help="Device file path")

    # Subparsers for actions
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Flash subcommand
    flash_parser = subparsers.add_parser("flash", help="Flash a file to the device")
    flash_parser.add_argument("input", type=str, help="File to flash")
    flash_parser.set_defaults(func=do_flash)

    # read subcommand
    read_parser = subparsers.add_parser("read", help="Read data from the device")
    read_parser.add_argument("address", type=lambda x: int(x, 16), help="Start address in hex")
    read_parser.add_argument("count", type=lambda x: int(x, 16), help="Number of bytes in hex")
    read_parser.add_argument("output", type=str, help="Output file for dumped data")
    read_parser.add_argument("--ignore_error", action="store_true", help="Ignore memory read errors and skip CRC check (default: False)")

    read_parser.set_defaults(func=do_read)

    # Parse arguments
    args = parser.parse_args()

    # Set logging level based on verbosity
    logging_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    logging_level = logging_levels[min(args.verbose, len(logging_levels) - 1)]
    logging.basicConfig(level=logging_level)

    if not args.device:
        logging.error(f'No wyze sense bridge device file specified or found!')
        return -1
    
    logging.info(f'Using bridge device {args.device}...')
    fd = dongle_open(args.device)

    logging.info("Requesting Upgrade Mode...")
    req = b'\x07\xAA\x55\x43\x03\x12\x01\x57'
    rawhid_write(fd, req)
    rsp = rawhid_read(fd)
    logging.info(f"rsp={hexify(rsp)}")

    logging.info("Requesting auto baud...")
    if not cmd_auto_baud(fd):
        logging.error(f'cmd_auto_baud failed')
        return -1

    logging.info("Sending ping command...")
    if not cmd_ping(fd):
        logging.error(f'cmd_ping failed')

    logging.info("Requesting Chip ID...")
    chipid = cmd_chip_id(fd)
    logging.info(f'Chip ID: {chipid:04X}')

    # Call the appropriate function
    if not args.func(fd, args):
        logging.error(f'Operation failed')
        return -1

    logging.info('Done!')
    cmd_reset(fd)
    return 0

if __name__ == "__main__":
    main()
