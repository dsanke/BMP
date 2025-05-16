from pathlib import Path
from io import BytesIO, StringIO
import argparse


class ssf_dat_struct:

    def __init__(self, value, ptr, size, offset):
        self.value = value
        self.ptr = ptr
        self.size = size
        self.offset = offset


def infix2postfix(op, dat_struct):
    res = []
    stack = ['#']
    isp = {
        '==': 5,
        '<': 5,
        '>': 5,
        '!=': 5,
        '<=': 5,
        '>=': 5,
        '||': 3,
        '&&': 3,
        '(': 1,
        ')': 6,
        '#': 0
    }
    icp = {
        '==': 4,
        '<': 4,
        '>': 4,
        '!=': 4,
        '<=': 4,
        '>=': 4,
        '||': 2,
        '&&': 2,
        '(': 6,
        ')': 1,
        '#': 0
    }
    i = 1
    while i < len(op):
        if op[i].startswith('$'):
            if dat_struct.get(op[i]):
                temp_value = int.from_bytes(dat_struct[op[i]].value,
                                            byteorder='little',
                                            signed=False)
                res.append(temp_value)
            i += 1
        elif op[i].isdigit() or op[i].startswith('0x'):
            res.append(int(op[i]))
            i += 1
        else:
            if isp[stack[-1]] < icp[op[i]]:
                stack.append(op[i])
                i += 1
            elif isp[stack[-1]] > icp[op[i]]:
                res.append(stack.pop())
            else:
                stack.pop()
                i += 1
    while stack[-1] != '#':
        res.append(stack.pop())
    return res


def calculate(res):
    stack = []
    for item in res:
        if isinstance(item, int):
            stack.append(item)
        else:
            right = stack.pop()
            left = stack.pop()
            ans = 0
            if item == '==':
                if left == right:
                    ans = 1
            elif item == '!=':
                if left != right:
                    ans = 1
            elif item == '>=':
                if left >= right:
                    ans = 1
            elif item == '<=':
                if left <= right:
                    ans = 1
            elif item == '>':
                if left > right:
                    ans = 1
            elif item == '<':
                if left < right:
                    ans = 1
            elif item == '||':
                ans = left | right
            elif item == '&&':
                ans = left & right
            stack.append(ans)
    return stack[0]


def bsf_line_process_read(bsf_line, offset_byte, offset_bit, dat_block_io,
                          dat_struct):
    op = bsf_line.split()
    if op[0].startswith('$'):
        dat_block_io.seek(offset_byte)
        if op[2].startswith('bit'):
            bytes_quantity = -(-int(op[1]) // 8)
            value_temp = int.from_bytes(dat_block_io.read(bytes_quantity),
                                        byteorder='little',
                                        signed=False)
            left_move = 8 * bytes_quantity - offset_bit - int(op[1])
            right_move = 8 * bytes_quantity - int(op[1])
            bytes_move_temp = b'\xFF' * bytes_quantity
            bytes_move_temp = int.from_bytes(bytes_move_temp,
                                             byteorder='little',
                                             signed=False)
            value_temp = (value_temp << left_move) & bytes_move_temp
            value_temp = (value_temp >> right_move) & bytes_move_temp
            value_temp = value_temp.to_bytes(length=bytes_quantity,
                                             byteorder='little',
                                             signed=False)
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit // 8
                offset_bit = offset_bit % 8
            dat_struct_temp = ssf_dat_struct(value_temp, 0, 0, 0)
            dat_struct[op[0]] = dat_struct_temp
        elif op[2].startswith('byte'):
            value_temp = dat_block_io.read(int(op[1]))
            offset_byte += int(op[1])
            dat_struct_temp = ssf_dat_struct(value_temp, 0, 0, 0)
            dat_struct[op[0]] = dat_struct_temp
        elif op[3] == 'Offset':
            dat_struct_temp = ssf_dat_struct(0, op[1].split(',')[0],
                                             op[2].split(',')[0], op[4])
            dat_struct[op[0].split(',')[0]] = dat_struct_temp
    elif op[0] == 'SKIP':
        if op[2].startswith('bit'):
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit // 8
                offset_bit = offset_bit % 8
        elif op[2].startswith('byte'):
            offset_byte += int(op[1])
    elif op[0] == 'ALIGN':
        if offset_bit != 0:
            offset_byte += 1
            offset_bit = 0
    return offset_byte, offset_bit


def bsf_line_process_write(bsf_line, offset_byte, offset_bit, dat_block_io,
                           dat_struct):
    op = bsf_line.split()
    if op[0].startswith('$'):
        if op[2].startswith('bit'):
            if dat_struct.get(op[0]):
                dat_block_io.seek(offset_byte)
                bytes_quantity = -(-int(op[1]) // 8)
                temp_for_clear_bits = b'\xFF' * bytes_quantity
                temp_for_clear_bits = int.from_bytes(temp_for_clear_bits,
                                                     byteorder='little',
                                                     signed=False)
                for i in range(0, int(op[1])):
                    temp_for_clear_bits &= ~(1 << (offset_bit + i))
                temp_for_original_bytes = int.from_bytes(
                    dat_block_io.read(bytes_quantity),
                    byteorder='little',
                    signed=False)
                temp_for_write = temp_for_clear_bits & temp_for_original_bytes
                temp_for_value = int.from_bytes(dat_struct[op[0]].value,
                                                byteorder='little',
                                                signed=False)
                temp_for_value = temp_for_value << offset_bit
                temp_for_write |= temp_for_value
                temp_for_write = temp_for_write.to_bytes(bytes_quantity,
                                                         byteorder='little',
                                                         signed=False)
                dat_block_io.seek(offset_byte)
                dat_block_io.write(temp_for_write)
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit // 8
                offset_bit = offset_bit % 8
        elif op[2].startswith('byte'):
            if dat_struct.get(op[0]):
                dat_block_io.seek(offset_byte)
                dat_temp = b'\x00' * int(op[1])
                dat_block_io.write(dat_temp)
                dat_block_io.seek(offset_byte)
                dat_temp = dat_struct[op[0]].value
                dat_block_io.write(dat_temp)
            offset_byte += int(op[1])
        elif op[3] == 'Offset':
            temp_key = op[0].split(',')[0]
            if dat_struct.get(temp_key):
                dat_block_io.seek(offset_byte)
                dat_struct[temp_key].offset = op[4]
                dat_struct[temp_key].ptr = op[1].split(',')[0]
                dat_struct[temp_key].size = op[2].split(',')[0]
    elif op[0] == 'SKIP':
        if op[2].startswith('bit'):
            offset_bit += int(op[1])
            if offset_bit >= 8:
                offset_byte += offset_bit // 8
                offset_bit = offset_bit % 8
        elif op[2].startswith('byte'):
            offset_byte += int(op[1])
    elif op[0] == 'ALIGN':
        if offset_bit != 0:
            offset_byte += 1
            offset_bit = 0
    return offset_byte, offset_bit


def save_ssf(dat_raw, bsf_io):
    dat_struct = dict()
    bsf_lines_struct = []
    while True:
        current_line = bsf_io.readline()
        if current_line.startswith('StructDef') is not True:
            pass
        else:
            current_line = bsf_io.readline()
            break
    while True:
        if current_line.startswith('EndStruct'):
            break
        else:
            bsf_lines_struct.append(current_line)
        current_line = bsf_io.readline()
    bsf_lines_page = []
    while True:
        if current_line == '':
            break
        else:
            bsf_lines_page.append(current_line)
        current_line = bsf_io.readline()
    offset_byte = 0
    offset_bit = 0
    for current_line in bsf_lines_struct:
        if current_line.isspace() or current_line.split(
        )[0] == ';' or current_line.split()[0] == 'Find':
            pass
        elif current_line.split()[0] == 'Find_Ptr_Ref' and current_line.split(
        )[1] == '"BIOS_DATA_BLOCK"':
            initial_offset = dat_raw.find(b'BIOS_DATA_BLOCK') + 16
            dat_io = BytesIO(dat_raw)
            dat_io.seek(initial_offset)
            dat_block_io = BytesIO(dat_io.read())
        else:
            temp = bsf_line_process_read(current_line, offset_byte, offset_bit,
                                         dat_block_io, dat_struct)
            offset_byte = temp[0]
            offset_bit = temp[1]
    data_type = ['Combo', 'Table', 'EditNum']
    str_type = ['MultiText', 'EditText']
    ssf_lines_raw = []
    no_skip = 1
    for current_line in bsf_lines_page:
        if current_line.isspace() or current_line.split()[0] == ';':
            continue
        op = current_line.split()
        if op[0].upper() == '#IF':
            current_line = current_line.split(';')[0]
            current_line = current_line.replace('(', ' ( ').replace(')', ' ) ')
            op = current_line.split()
            op = infix2postfix(op, dat_struct)
            op = calculate(op)
            no_skip = op & no_skip
        elif op[0].upper() == '#ELSEIF':
            current_line = current_line.split(';')[0]
            current_line = current_line.replace('(', ' ( ').replace(')', ' ) ')
            op = current_line.split()
            op = infix2postfix(op, dat_struct)
            op = calculate(op)
            no_skip = op
        elif op[0].upper() == '#ELSE':
            no_skip = not no_skip
        elif op[0].upper() == '#ENDIF':
            no_skip = 1
        elif no_skip == 0:
            pass
        elif op[0] == 'Page':
            ssf_lines_raw.append('\n' + 'PAGE ' + current_line.split('"')[1] +
                                 '\n')
        elif op[0] in data_type:
            if op[0] == 'Combo' or op[0] == 'EditNum':
                op2 = op[1].split(',')[0]
                if dat_struct.get(op2):
                    ssf_lines_raw.append(op2 + ' ' + ' '.join(
                        '{:02X}'.format(b)
                        for b in dat_struct[op2].value) + '\n')
            elif op[0] == 'Table':
                if dat_struct.get(op[1]):
                    if dat_struct[op[1]].ptr != 0:
                        if dat_struct.get(dat_struct[op[1]].ptr):
                            table_ptr = int.from_bytes(
                                dat_struct[dat_struct[op[1]].ptr].value,
                                byteorder='little',
                                signed=False) + int(
                                    dat_struct[op[1]].offset) - 16
                        if dat_struct.get(dat_struct[op[1]].size):
                            table_size = int.from_bytes(
                                dat_struct[dat_struct[op[1]].size].value,
                                byteorder='little',
                                signed=False)
                        dat_block_io.seek(table_ptr)
                        dat_struct[op[1]].value = dat_block_io.read(table_size)
                    ssf_lines_raw.append('TABLE ' + op[1] + ' ' + ' '.join(
                        '{:02X}'.format(b)
                        for b in dat_struct[op[1]].value) + '\n')
        elif op[0] in str_type:
            op2 = op[1].split(',')[0]
            if dat_struct.get(op2):
                ssf_lines_raw.append(
                    'STRING ' + op2 + ' ' +
                    dat_struct[op2].value.replace(b'\x0D\x0A', b'\\r\\n').
                    decode().strip(b'\x00'.decode()) + '\n')
    return ssf_lines_raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dat_file', type=str)
    parser.add_argument('bsf_file', type=str)

    args = parser.parse_args()

    dat_file = Path.cwd().joinpath(args.dat_file.lstrip('\\'))
    bsf_file = Path.cwd().joinpath(args.bsf_file.lstrip('\\'))
    ssf_file = Path.cwd().joinpath('data', 'tmp', 'settings.ssf')

    with open(str(dat_file), 'rb') as f:
        dat_raw = f.read()
    with open(str(bsf_file), encoding='utf-8', errors='ignore', mode='r') as f:
        bsf_io = StringIO(f.read())
    ssf_raw = save_ssf(dat_raw, bsf_io)
    with open(str(ssf_file), encoding='utf-8', mode='w', newline='\r\n') as f:
        f.writelines(ssf_raw)


if __name__ == "__main__":
    main()
