from pathlib import Path
from io import BytesIO
import argparse


class ssf_dat_struct:
    def __init__(self, name, value, ptr, size, offset):
        self.name = name
        self.value = value
        self.ptr = ptr
        self.size = size
        self.offset = offset


def save_ssf(dat_file, bsf_file, ssf_file):
    dat = open(dat_file, 'rb')
    dat_raw = dat.read()
    dat.close()
    bsf = open(bsf_file, encoding='utf-8', errors='ignore', mode='r')
    dat_struct = []
    bsf_lines_struct = []
    while True:
        current_line = bsf.readline()
        if current_line.startswith('StructDef') is not True:
            pass
        else:
            break
    while True:
        if current_line.startswith('EndStruct'):
            break
        else:
            bsf_lines_struct.append(current_line)
        current_line = bsf.readline()
    bsf_lines_page = []
    while True:
        if current_line == '':
            break
        else:
            bsf_lines_page.append(current_line)
        current_line = bsf.readline()
    bsf.close()
    offset_byte = 0
    offset_bit = 0
    for current_line in bsf_lines_struct:
        if current_line.startswith(';') or current_line.isspace() or current_line.split()[0] == 'Find':
            pass
        elif current_line.split()[0] == 'Find_Ptr_Ref' and current_line.split()[1] == '"BIOS_DATA_BLOCK"':
            initial_offset = dat_raw.find(b'BIOS_DATA_BLOCK') + 16
            dat = BytesIO(dat_raw)
            dat.seek(initial_offset)
            dat_raw = BytesIO(dat.read())
        else:
            temp = bsf_line_process_read(current_line, offset_byte, offset_bit, dat_raw, dat_struct)
            offset_byte = temp[0]
            offset_bit = temp[1]
    data_type = ['Combo', 'Table', 'EditNum']
    str_type = ['MultiText', 'EditText']
    ssf_raw = []
    skip = False
    for current_line in bsf_lines_page:
        if current_line.startswith(';') or current_line.isspace() or current_line.startswith('$'):
            continue
        op = current_line.split()
        if op[0] == '#IF':
            bsf_condition = op[1].replace('(', '')
            bsf_value = op[3].replace(')', '')
            for x in dat_struct:
                if x.name == bsf_condition:
                    if x.value != bsf_value:
                        skip = True
        elif op[0] == '#ELSE' or op[0] == '#ENDIF':
            skip = False
        elif skip:
            pass
        elif op[0] == 'Page':
            ssf_raw.append('\n' + 'PAGE ' + current_line.split('"')[1] + '\n')
        elif op[0] in data_type:
            if op[0] == 'Combo' or op[0] == 'EditNum':
                op2 = op[1].split(',')[0]
                for x in dat_struct:
                    if x.name == op2:
                        ssf_raw.append(x.name + ' ' + x.value.hex(' ').upper() + '\n')
            elif op[0] == 'Table':
                for x in dat_struct:
                    if x.name == op[1]:
                        if x.ptr != 0:
                            for y in dat_struct:
                                if y.name == x.ptr:
                                    table_ptr = int.from_bytes(y.value, byteorder='little', signed=False) + int(x.offset) - 16
                            for y in dat_struct:
                                if y.name == x.size:
                                    table_size = int.from_bytes(y.value, byteorder='little', signed=False)
                            dat_raw.seek(table_ptr)
                            x.value = dat_raw.read(table_size)
                        ssf_raw.append('TABLE ' + x.name + ' ' + x.value.hex(' ').upper() + '\n')
        elif op[0] in str_type:
            op2 = op[1].split(',')[0]
            for x in dat_struct:
                if x.name == op2:
                    ssf_raw.append('STRING ' + x.name + ' ' + x.value.replace(b'\x0D\x0A', b'\\r\\n').decode().strip(b'\x00'.decode()) + '\n')
    ssf = open(ssf_file, encoding='utf-8', mode='w', newline='\r\n')
    ssf.writelines(ssf_raw)
    ssf.close()
    return 0


def apply_ssf(dat_file, bsf_file, ssf_file, new_dat_file):
    dat = open(dat_file, 'rb')
    dat_raw = dat.read()
    dat.close()
    ssf = open(ssf_file, encoding='utf-8', errors='ignore', mode='r')
    ssf_lines = []
    while True:
        current_line = ssf.readline()
        if not current_line:
            break
        elif current_line.startswith('PAGE') or current_line.isspace():
            pass
        else:
            ssf_lines.append(current_line)
    ssf.close()
    dat_struct = []
    for current_line in ssf_lines:
        op = current_line.split(' ', 1)
        if op[0] == 'STRING':
            op = op[1].split(' ', 1)
            dat_temp = op[1].split('\n', 1)[0].encode('ASCII').replace(b'\\r\\n', b'\r\n')
            dat_struct_temp = ssf_dat_struct(op[0], dat_temp, 0, 0, 0)
            dat_struct.append(dat_struct_temp)
        elif op[0] == 'TABLE':
            op = op[1].split(' ', 1)
            dat_temp = bytes.fromhex(op[1].strip())
            dat_struct_temp = ssf_dat_struct(op[0], dat_temp, 0, 0, 0)
            dat_struct.append(dat_struct_temp)
        elif op[0].startswith('$'):
            temp = op[1].strip()
            if len(temp) == 1:
                temp = '0' + temp
            dat_temp = bytes.fromhex(temp)
            dat_struct_temp = ssf_dat_struct(op[0], dat_temp, 0, 0, 0)
            dat_struct.append(dat_struct_temp)
    bsf = open(bsf_file, encoding='utf-8', errors='ignore', mode='r')
    bsf_lines_struct = []
    while True:
        current_line = bsf.readline()
        if current_line.startswith('StructDef') is not True:
            pass
        else:
            break
    while True:
        if current_line.startswith('EndStruct'):
            break
        else:
            bsf_lines_struct.append(current_line)
        current_line = bsf.readline()
    bsf_lines_page = []
    while True:
        if current_line == '':
            break
        else:
            bsf_lines_page.append(current_line)
        current_line = bsf.readline()
    bsf.close()
    offset_byte = 0
    offset_bit = 0
    for current_line in bsf_lines_struct:
        if current_line.startswith(';') or current_line.isspace() or current_line.split()[0] == 'Find':
            pass
        elif current_line.split()[0] == 'Find_Ptr_Ref' and current_line.split()[1] == '"BIOS_DATA_BLOCK"':
            initial_offset = dat_raw.find(b'BIOS_DATA_BLOCK') + 16
            dat = BytesIO(dat_raw)
            dat.seek(initial_offset)
            dat_raw = BytesIO(dat.read())
        elif '_Ptr' in current_line.split()[0] or '_Size' in current_line.split()[0]:
            temp = bsf_line_process_read(current_line, offset_byte, offset_bit, dat_raw, dat_struct)
            offset_byte = temp[0]
            offset_bit = temp[1]
        else:
            temp = bsf_line_process_write(current_line, offset_byte, offset_bit, dat_raw, dat_struct)
            offset_byte = temp[0]
            offset_bit = temp[1]
    for current_line in bsf_lines_page:
        if current_line.startswith(';') or current_line.isspace() or current_line.startswith('$'):
            continue
        op = current_line.split()
        if op[0] == 'Table':
            for x in dat_struct:
                if x.name == op[1]:
                    if x.ptr != 0:
                        table_ptr = ''
                        table_size = ''
                        for y in dat_struct:
                            if y.name == x.ptr:
                                table_ptr = int.from_bytes(y.value, byteorder='little', signed=False) + int(x.offset) - 16
                        for y in dat_struct:
                            if y.name == x.size:
                                table_size = int.from_bytes(y.value, byteorder='little', signed=False)
                        if table_ptr == '' and table_size == '':
                            pass
                        else:
                            dat_raw.seek(table_ptr)
                            dat_temp = b'\x00' * table_size
                            dat_raw.write(dat_temp)
                            dat_raw.seek(table_ptr)
                            dat_raw.write(x.value)
    dat = open(dat_file, mode='rb')
    dat_raw.seek(0)
    dat_raw = dat.read(initial_offset) + dat_raw.read()
    dat.close()
    checksum_offset = dat_raw.find(b'BIOS_DATA_BLOCK') - 22
    dat_raw = BytesIO(dat_raw)
    checksum = 0
    dat_raw.seek(checksum_offset)
    dat_raw.write(checksum.to_bytes(1, byteorder='little'))
    dat_raw.seek(0)
    while True:
        temp = dat_raw.read(1)
        if not temp:
            break
        checksum += int.from_bytes(temp, byteorder='little', signed=False)
        checksum &= 0xFF
    if checksum == 0:
        pass
    else:
        checksum = 0x100 - checksum
    dat_raw.seek(checksum_offset)
    dat_raw.write(checksum.to_bytes(1, byteorder='little'))
    dat_raw.seek(0)
    dat_raw = dat_raw.read()
    dat = open(new_dat_file, mode='wb')
    dat.write(dat_raw)
    dat.close()
    return 0


def bsf_line_process_read(bsf_line, offset_byte, offset_bit, dat_raw, dat_struct):
    op = bsf_line.split()
    if op[0].startswith('$'):
        dat_raw.seek(offset_byte)
        if op[2].startswith('bit'):
            dat_temp = int.from_bytes(dat_raw.read(1), byteorder='little', signed=False)
            left_move = 8 - offset_bit - int(op[1])
            right_move = 8 - int(op[1])
            dat_temp = (dat_temp << left_move) & 255
            dat_temp = (dat_temp >> right_move) & 255
            dat_temp = dat_temp.to_bytes(length=1, byteorder='little', signed=False)
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit//8
                offset_bit = offset_bit % 8
            dat_struct_temp = ssf_dat_struct(op[0], dat_temp, 0, 0, 0)
            dat_struct.append(dat_struct_temp)
        elif op[2].startswith('byte'):
            dat_temp = dat_raw.read(int(op[1]))
            offset_byte += int(op[1])
            dat_struct_temp = ssf_dat_struct(op[0], dat_temp, 0, 0, 0)
            dat_struct.append(dat_struct_temp)
        elif op[3] == 'Offset':
            dat_struct_temp = ssf_dat_struct(op[0].split(',')[0], 0, op[1].split(',')[0], op[2].split(',')[0], op[4])
            dat_struct.append(dat_struct_temp)
    elif op[0] == 'SKIP':
        if op[2].startswith('bit'):
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit//8
                offset_bit = offset_bit % 8
        elif op[2].startswith('byte'):
            offset_byte += int(op[1])
    elif op[0] == 'ALIGN':
        if offset_bit != 0:
            offset_byte += 1
            offset_bit = 0
    return offset_byte, offset_bit


def bsf_line_process_write(bsf_line, offset_byte, offset_bit, dat_raw, dat_struct):
    op = bsf_line.split()
    if op[0].startswith('$'):
        dat_raw.seek(offset_byte)
        if op[2].startswith('bit'):
            for x in dat_struct:
                if x.name == op[0]:
                    dat_write_temp = (2 << (int(op[1]) - 1)) - 1
                    dat_write_temp = dat_write_temp << offset_bit
                    dat_read_temp = int.from_bytes(dat_raw.read(1), byteorder='little', signed=False)
                    dat_temp = dat_write_temp | dat_read_temp
                    dat_write_temp = dat_write_temp ^ 255
                    dat_write_temp2 = int.from_bytes(x.value, byteorder='little', signed=False)
                    dat_write_temp2 = dat_write_temp2 << offset_bit
                    dat_write_temp2 = dat_write_temp | dat_write_temp2
                    dat_temp = dat_write_temp2 & dat_temp
                    dat_temp = dat_temp.to_bytes(1, byteorder='little', signed=False)
                    dat_raw.seek(offset_byte)
                    dat_raw.write(dat_temp)
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit//8
                offset_bit = offset_bit % 8
        elif op[2].startswith('byte'):
            for x in dat_struct:
                if x.name == op[0]:
                    dat_temp = b'\x00' * int(op[1])
                    dat_raw.write(dat_temp)
                    dat_raw.seek(offset_byte)
                    dat_temp = x.value
                    dat_raw.write(dat_temp)
            offset_byte += int(op[1])
        elif op[3] == 'Offset':
            for x in dat_struct:
                if x.name == op[0].split(',')[0]:
                    x.offset = op[4]
                    x.ptr = op[1].split(',')[0]
                    x.size = op[2].split(',')[0]
    elif op[0] == 'SKIP':
        if op[2].startswith('bit'):
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit//8
                offset_bit = offset_bit % 8
        elif op[2].startswith('byte'):
            offset_byte += int(op[1])
    elif op[0] == 'ALIGN':
        if offset_bit != 0:
            offset_byte += 1
            offset_bit = 0
    return offset_byte, offset_bit


def main():
    parser = argparse.ArgumentParser(description='CLI substitution of Intel BMP, written in Python.')
    parser.add_argument('dat_file', metavar='DAT', type=str, help='binary file path')
    parser.add_argument('bsf_file', metavar='BSF', type=str, help='script file path')
    parser.add_argument('ssf_file', metavar='SSF', type=str, help='settings file path')
    parser.add_argument('new_dat_file', metavar='nDAT', type=str, nargs='?', help='new binary file path')
    parser.add_argument('-s', action='store_true', help='Apply settings to binary file.')
    parser.add_argument('-b', action='store_true', help='Save settings from binary file.')

    args = parser.parse_args()

    if not (args.s or args.b):
        parser.error('No action requested, add -s or -b')

    if args.s and args.b:
        parser.error('Too many actions requested, use -s or -b only')

    dat_file = Path.cwd().joinpath(args.dat_file)
    bsf_file = Path.cwd().joinpath(args.bsf_file)
    ssf_file = Path.cwd().joinpath(args.ssf_file)

    if not dat_file.is_file():
        parser.error('invalid dat file.')
        return -1

    if not bsf_file.is_file():
        parser.error('invalid bsf file.')
        return -1

    if args.s:
        if not ssf_file.is_file():
            parser.error('invalid ssf file.')
            return -1
        if args.new_dat_file:
            new_dat_file = Path.cwd().joinpath(args.new_dat_file)
        else:
            new_dat_file = dat_file

    if args.s:
        return apply_ssf(dat_file, bsf_file, ssf_file, new_dat_file)
    elif args.b:
        return save_ssf(dat_file, bsf_file, ssf_file)


if __name__ == "__main__":
    main()
