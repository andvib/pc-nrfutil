#
# Copyright (c) 2016 Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# Python standard library
import os
import time
import shutil
import logging
import tempfile
import struct
import binascii
from enum import Enum

# Nordic libraries
from nordicsemi.dfu import intelhex
from nordicsemi.dfu.intelhex import IntelHex, IntelHexError
from nordicsemi.dfu.nrfhex import *
from nordicsemi.dfu.package import Package
from pc_ble_driver_py.exceptions import NordicSemiException

from .signing import Signing

logger = logging.getLogger(__name__)

class BLDFUSettingsStructV1(object):

    def __init__(self):
        self.uint32_count = (4 + 2 + (3 * 2) + 2 + (3 + 1 + 4) + 1)
        self.offs_crc               = 0
        self.offs_sett_ver          = 1
        self.offs_app_ver           = 2
        self.offs_bl_ver            = 3
        self.offs_bank_layout       = 4
        self.offs_bank_current      = 5
        self.offs_bank0_img_sz      = 6
        self.offs_bank0_img_crc     = 7
        self.offs_bank0_bank_code   = 8

class BLDFUSettingsStructV2(object):

    def __init__(self, settings_address):
        self.bytes_count = 256 # Entire settings page
        self.crc                  = settings_address + 0x0
        self.sett_ver             = settings_address + 0x4
        self.app_ver              = settings_address + 0x8
        self.bl_ver               = settings_address + 0xC
        self.bank_layout          = settings_address + 0x10
        self.bank_current         = settings_address + 0x14
        self.bank0_img_sz         = settings_address + 0x18
        self.bank0_img_crc        = settings_address + 0x1C
        self.bank0_bank_code      = settings_address + 0x20
        self.sd_sz                = settings_address + 0x34

        self.sd_validation_type   = settings_address + 0x9C
        self.sd_validation_bytes  = settings_address + 0x9D
        self.app_validation_type  = settings_address + 0xDD
        self.app_validation_bytes = settings_address + 0xDE

        self.last_addr            = settings_address + 0x15E

class BLDFUSettings(object):
    """ Class to abstract a bootloader and its settings """

    flash_page_51_sz     = 0x400
    flash_page_52_sz     = 0x1000
    bl_sett_51_addr      = 0x0003FC00
    bl_sett_52_addr      = 0x0007F000
    bl_sett_52_qfab_addr = 0x0003F000
    bl_sett_52810_addr   = 0x0002F000
    bl_sett_52840_addr   = 0x000FF000


    def __init__(self, ):
        """
        """
        # instantiate a hex object
        self.ihex = intelhex.IntelHex()
        self.temp_dir = None
        self.hex_file = ""

    def __del__(self):
        """
        Destructor removes the temporary directory
        :return:
        """
        if self.temp_dir is not None:
            shutil.rmtree(self.temp_dir)

    def set_arch(self, arch):
        if arch == 'NRF51':
            self.arch = nRFArch.NRF51
            self.arch_str = 'nRF51'
            self.flash_page_sz = BLDFUSettings.flash_page_51_sz
            self.bl_sett_addr = BLDFUSettings.bl_sett_51_addr
        elif arch == 'NRF52':
            self.arch = nRFArch.NRF52
            self.arch_str = 'nRF52'
            self.flash_page_sz = BLDFUSettings.flash_page_52_sz
            self.bl_sett_addr = BLDFUSettings.bl_sett_52_addr
        elif arch == 'NRF52QFAB':
            self.arch = nRFArch.NRF52
            self.arch_str = 'nRF52QFAB'
            self.flash_page_sz = BLDFUSettings.flash_page_52_sz
            self.bl_sett_addr = BLDFUSettings.bl_sett_52_qfab_addr
        elif arch == 'NRF52810':
            self.arch = nRFArch.NRF52
            self.arch_str = 'NRF52810'
            self.flash_page_sz = BLDFUSettings.flash_page_52_sz
            self.bl_sett_addr = BLDFUSettings.bl_sett_52810_addr
        elif arch == 'NRF52840':
            self.arch = nRFArch.NRF52840
            self.arch_str = 'NRF52840'
            self.flash_page_sz = BLDFUSettings.flash_page_52_sz
            self.bl_sett_addr = BLDFUSettings.bl_sett_52840_addr
        else:
            raise RuntimeError("Unknown architecture")

    def fromhexfile(self, f, arch=None):
        self.hex_file = f
        self.ihex.fromfile(f, format='hex')

        # check the 3 possible addresses for CRC matches
        try:
            self.probe_settings(BLDFUSettings.bl_sett_51_addr)
            self.set_arch('NRF51')
        except Exception as e:
            try:
                self.probe_settings(BLDFUSettings.bl_sett_52_addr)
                self.set_arch('NRF52')
            except Exception as e:
                try:
                    self.probe_settings(BLDFUSettings.bl_sett_52_qfab_addr)
                    self.set_arch('NRF52QFAB')
                except Exception as e:
                    try:
                        self.probe_settings(BLDFUSettings.bl_sett_52810_addr)
                        self.set_arch('NRF52810')
                    except Exception as e:
                        try:
                            self.probe_settings(BLDFUSettings.bl_sett_52840_addr)
                            self.set_arch('NRF52840')
                        except Exception as e:
                            raise NordicSemiException("Failed to parse .hex file: {0}".format(e))

        self.bl_sett_addr = self.ihex.minaddr()

    def tohexfile(self, f):
        self.hex_file = f
        self.ihex.tofile(f, format='hex')

class BLDFUSettingsV1(BLDFUSettings):

    def __init__(self):
        super(BLDFUSettingsV1, self).__init__()

    def generate(self, arch, app_file, app_ver, bl_ver, bl_sett_ver, custom_bl_sett_addr):
        """
        Populates the settings object based on the given parameters.

        :param arch: Architecture family string, e.g. NRF51
        :param app_file: Path to application file
        :param app_ver: Application version number
        :param bl_ver: Bootloader version number
        :param bl_sett_ver: Bootloader settings version number
        :param custom_bl_sett_addr: Custom start address for the settings page
        :return:
        """

        # Set the architecture
        self.set_arch(arch)

        if custom_bl_sett_addr is not None:
            self.bl_sett_addr = custom_bl_sett_addr

        self.setts = BLDFUSettingsStructV1()

        self.bl_sett_ver = bl_sett_ver & 0xffffffff
        self.bl_ver = bl_ver & 0xffffffff

        if app_ver is not None:
            self.app_ver = app_ver & 0xffffffff
        else:
            self.app_ver = 0x0 & 0xffffffff

        if app_file is not None:
            # load application to find out size and CRC
            self.temp_dir = tempfile.mkdtemp(prefix="nrf_dfu_bl_sett_")
            self.app_bin = Package.normalize_firmware_to_bin(self.temp_dir, app_file)

            # calculate application size and CRC32
            self.app_sz = int(Package.calculate_file_size(self.app_bin)) & 0xffffffff
            self.app_crc = int(Package.calculate_crc(32, self.app_bin)) & 0xffffffff
            self.bank0_bank_code = 0x1 & 0xffffffff

        else:
            self.app_sz = 0x0 & 0xffffffff
            self.app_crc = 0x0 & 0xffffffff
            self.bank0_bank_code = 0x0 & 0xffffffff

        # build the uint32_t array
        arr = [0x0] * self.setts.uint32_count
        # additional harcoded values
        self.bank_layout = 0x0 & 0xffffffff
        self.bank_current = 0x0 & 0xffffffff

        # fill in the settings
        arr[self.setts.offs_sett_ver] = self.bl_sett_ver
        arr[self.setts.offs_app_ver] = self.app_ver
        arr[self.setts.offs_bl_ver] = self.bl_ver
        arr[self.setts.offs_bank_layout] = self.bank_layout
        arr[self.setts.offs_bank_current] = self.bank_current
        arr[self.setts.offs_bank0_img_sz] = self.app_sz
        arr[self.setts.offs_bank0_img_crc] = self.app_crc
        arr[self.setts.offs_bank0_bank_code] = self.bank0_bank_code

        # calculate the CRC32 from the filled-in settings
        crc_format_str = '<' + ('I' * (self.setts.uint32_count - 1))
        crc_arr = arr[1:]
        crc_data = struct.pack(crc_format_str, *crc_arr)
        self.crc = binascii.crc32(crc_data) & 0xffffffff

        # fill in the calculated CRC32
        arr[self.setts.offs_crc] = self.crc

        format_str = '<' + ('I' * self.setts.uint32_count)

        # Get the packed data to insert into the hex instance
        data = struct.pack(format_str, *arr)

        # insert the data at the correct address
        self.ihex.puts(self.bl_sett_addr, data)

    def probe_settings(self, base):

        # Unpack CRC and version
        fmt = '<I'

        crc = struct.unpack(fmt, self.ihex.gets(base + 0, 4))[0] & 0xffffffff
        ver = struct.unpack(fmt, self.ihex.gets(base + 4, 4))[0] & 0xffffffff

        if ver == 1:
            self.setts = BLDFUSettingsStructV1()
        else:
            raise RuntimeError("Unknown Bootloader DFU settings version: {0}".format(ver))

        # calculate the CRC32 over the data
        crc_data = self.ihex.gets(base + 4, (self.setts.uint32_count - 1) * 4)
        _crc = binascii.crc32(crc_data) & 0xffffffff

        if _crc != crc:
            raise RuntimeError("CRC32 mismtach: flash: {0} calculated: {1}".format(crc, _crc))

        self.crc = crc

        fmt = '<' + ('I' * (self.setts.uint32_count))
        arr = struct.unpack(fmt, self.ihex.gets(base, (self.setts.uint32_count) * 4))

        self.bl_sett_ver = arr[self.setts.offs_sett_ver] & 0xffffffff
        self.app_ver = arr[self.setts.offs_app_ver] & 0xffffffff
        self.bl_ver = arr[self.setts.offs_bl_ver] & 0xffffffff
        self.bank_layout = arr[self.setts.offs_bank_layout] & 0xffffffff
        self.bank_current = arr[self.setts.offs_bank_current] & 0xffffffff
        self.app_sz = arr[self.setts.offs_bank0_img_sz] & 0xffffffff
        self.app_crc = arr[self.setts.offs_bank0_img_crc] & 0xffffffff
        self.bank0_bank_code = arr[self.setts.offs_bank0_bank_code] & 0xffffffff

    def __str__(self):
        s = """
Bootloader DFU Settings:
* File:                 {0}
* Family:               {1}
* Start Address:        0x{2:08X}
* CRC:                  0x{3:08X}
* Settings Version:     0x{4:08X} ({4})
* App Version:          0x{5:08X} ({5})
* Bootloader Version:   0x{6:08X} ({6})
* Bank Layout:          0x{7:08X}
* Current Bank:         0x{8:08X}
* Application Size:     0x{9:08X} ({9} bytes)
* Application CRC:      0x{10:08X}
* Bank0 Bank Code:      0x{11:08X}
""".format(self.hex_file, self.arch_str, self.bl_sett_addr, self.crc,
           self.bl_sett_ver, self.app_ver, self.bl_ver, self.bank_layout,
           self.bank_current, self.app_sz, self.app_crc, self.bank0_bank_code)
        return s


class BLDFUSettingsV2(BLDFUSettings):

    def __init__(self):
        super(BLDFUSettingsV2, self).__init__()

    def _add_value_tohex(self, addr, value, format='<I'):
        self.ihex.puts(addr, struct.pack(format, value))

    def generate(self, arch, app_file, app_ver, bl_ver, bl_sett_ver, custom_bl_sett_addr,
                 app_boot_validation_type, sd_boot_validation_type, sd_file, key_file):

        self.set_arch(arch)

        if custom_bl_sett_addr is not None:
            self.bl_sett_addr = custom_bl_sett_addr

        self.setts = BLDFUSettingsStructV2(self.bl_sett_addr)

        self.bl_sett_ver = bl_sett_ver & 0xffffffff
        self.bl_ver = bl_ver & 0xffffffff

        if app_ver is not None:
            self.app_ver = app_ver & 0xffffffff
        else:
            self.app_ver = 0x0 & 0xffffffff

        if app_file is not None:
            # load application to find out size and CRC
            self.temp_dir = tempfile.mkdtemp(prefix="nrf_dfu_bl_sett_")
            self.app_bin = Package.normalize_firmware_to_bin(self.temp_dir, app_file)

            # calculate application size and CRC32
            self.app_sz = int(Package.calculate_file_size(self.app_bin)) & 0xffffffff
            self.app_crc = int(Package.calculate_crc(32, self.app_bin)) & 0xffffffff
            self.bank0_bank_code = 0x1 & 0xffffffff

            # Calculate Boot validation fields for app
            if app_boot_validation_type == 'VALIDATE_GENERATED_CRC':
                self.app_boot_validation_type = 1 & 0xffffffff
                self.app_boot_validation_bytes = struct.pack('<I', self.app_crc)
            elif app_boot_validation_type == 'VALIDATE_GENERATED_SHA256':
                self.app_boot_validation_type = 2 & 0xffffffff
                sha256 = Package.calculate_sha256_hash(self.app_bin)
                self.app_boot_validation_bytes = bytearray([int(binascii.hexlify(i), 16) for i in list(sha256)][31::-1])
            elif app_boot_validation_type == 'VALIDATE_ECDSA_P256_SHA256':
                self.app_boot_validation_type = 3 & 0xffffffff
                ecdsa = Package.sign_firmware(key_file, self.app_bin)
                self.app_boot_validation_bytes = bytearray([int(binascii.hexlify(i), 16) for i in list(ecdsa)])
            else:  # This also covers 'NO_VALIDATION' case
                self.app_boot_validation_type = 0 & 0xffffffff
                self.app_boot_validation_bytes = 0 & 0xffffffff
        else:
            self.app_sz = 0x0 & 0xffffffff
            self.app_crc = 0x0 & 0xffffffff
            self.bank0_bank_code = 0x0 & 0xffffffff
            self.app_boot_validation_type = 0x0 & 0xffffffff
            self.app_boot_validation_bytes = 0x0 & 0xffffffff

        if sd_file is not None:
            # Load SD to calculate CRC
            self.temp_dir = tempfile.mkdtemp(prefix="nrf_dfu_bl_sett")
            temp_sd_file = os.path.join(os.getcwd(), 'temp_sd_file.hex')

            # Load SD hex file and remove MBR before calculating keys
            ih_sd = IntelHex(sd_file)
            ih_sd_no_mbr = IntelHex()
            ih_sd_no_mbr.merge(ih_sd[0x1000:], overlap='error')
            ih_sd_no_mbr.write_hex_file(temp_sd_file)

            self.sd_bin = Package.normalize_firmware_to_bin(self.temp_dir, temp_sd_file)
            os.remove(temp_sd_file)

            self.sd_sz = int(Package.calculate_file_size(self.sd_bin)) & 0xffffffff

            # Calculate Boot validation fields for SD
            if sd_boot_validation_type == 'VALIDATE_GENERATED_CRC':
                self.sd_boot_validation_type = 1 & 0xffffffff
                sd_crc = int(Package.calculate_crc(32, self.sd_bin)) & 0xffffffff
                self.sd_boot_validation_bytes = struct.pack('<I', sd_crc)
                print(self.sd_boot_validation_bytes)
            elif sd_boot_validation_type == 'VALIDATE_GENERATED_SHA256':
                self.sd_boot_validation_type = 2 & 0xffffffff
                sha256 = Package.calculate_sha256_hash(self.sd_bin)
                self.sd_boot_validation_bytes = bytearray([int(binascii.hexlify(i), 16) for i in list(sha256)][31::-1])
            elif sd_boot_validation_type == 'VALIDATE_ECDSA_P256_SHA256':
                self.sd_boot_validation_type = 3 & 0xffffffff
                ecdsa = Package.sign_firmware(key_file, self.sd_bin)
                self.sd_boot_validation_bytes = bytearray([int(binascii.hexlify(i), 16) for i in list(ecdsa)])
            else: # This also covers 'NO_VALIDATION_CASE'
                self.sd_boot_validation_type = 0 & 0xffffffff
                self.sd_boot_validation_bytes = 0 & 0xffffffff
        else:
            self.sd_sz = 0x0 & 0xffffffff
            self.sd_boot_validation_type = 0 & 0xffffffff
            self.sd_boot_validation_bytes = 0 & 0xffffffff

        # additional harcoded values
        self.bank_layout = 0x0 & 0xffffffff
        self.bank_current = 0x0 & 0xffffffff

        # Fill the entire settings page with 0's
        for addr in range(self.bl_sett_addr, self.setts.last_addr + 1):
            self.ihex[addr] = 0x00

        self._add_value_tohex(self.setts.sett_ver, self.bl_sett_ver)
        self._add_value_tohex(self.setts.app_ver, self.app_ver)
        self._add_value_tohex(self.setts.bl_ver, self.bl_ver)
        self._add_value_tohex(self.setts.bank_layout, self.bank_layout)
        self._add_value_tohex(self.setts.bank_current, self.bank_current)
        self._add_value_tohex(self.setts.bank0_img_sz, self.app_sz)
        self._add_value_tohex(self.setts.bank0_img_crc, self.app_crc)
        self._add_value_tohex(self.setts.bank0_bank_code, self.bank0_bank_code)
        self._add_value_tohex(self.setts.sd_sz, self.sd_sz)

        self._add_value_tohex(self.setts.sd_validation_type, self.sd_boot_validation_type, '<b')
        self.ihex.puts(self.setts.sd_validation_bytes, self.sd_boot_validation_bytes)

        self._add_value_tohex(self.setts.app_validation_type, self.app_boot_validation_type, '<b')
        self.ihex.puts(self.setts.app_validation_bytes, self.app_boot_validation_bytes)

        byte_list = []
        hex_dict = self.ihex.todict()
        for addr, byte in hex_dict.items():
            if addr >= self.setts.sett_ver and addr <= self.setts.last_addr:
                byte_list.append(byte)

        self.crc = binascii.crc32(bytearray(byte_list)) & 0xffffffff

        self._add_value_tohex(self.setts.crc, self.crc)

    def __str__(self):
        s = """
Bootloader DFU Settings:
* File:                     {0}
* Family:                   {1}
* Start Address:            0x{2:08X}
* CRC:                      0x{3:08X}
* Settings Version:         0x{4:08X} ({4})
* App Version:              0x{5:08X} ({5})
* Bootloader Version:       0x{6:08X} ({6})
* Bank Layout:              0x{7:08X}
* Current Bank:             0x{8:08X}
* Application Size:         0x{9:08X} ({9} bytes)
* Application CRC:          0x{10:08X}
* Bank0 Bank Code:          0x{11:08X}
* Softdevice Size:          0x{12:08X} ({12} bytes)
* SD Boot Validation Type:  0x{13:08X} ({13})
* App Boot Validation Type: 0x{14:08X} ({14})
""".format(self.hex_file, self.arch_str, self.bl_sett_addr, self.crc,
           self.bl_sett_ver, self.app_ver, self.bl_ver, self.bank_layout,
           self.bank_current, self.app_sz, self.app_crc, self.bank0_bank_code,
           self.sd_sz, self.sd_boot_validation_type, self.app_boot_validation_type)
        return s
