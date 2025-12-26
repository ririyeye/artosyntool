import csv
import json
import math
import sys
import os

def parse_bit_range(range_str):
    # Parse "[25:24]" or "[7:0]"
    if not range_str.startswith('[') or not range_str.endswith(']'):
        return None
    content = range_str[1:-1]
    if ':' in content:
        parts = content.split(':')
        return int(parts[0]), int(parts[1])
    else:
        val = int(content)
        return val, val

def get_reg_key(item):
    # Construct the CSV header key based on page and offset
    # Format: reg_p{page}_0x{offset:02X}
    page = item.get('page', 0)
    offset_str = str(item.get('offset', '0'))
    
    if offset_str.startswith('0x') or offset_str.startswith('0X'):
        offset = int(offset_str, 16)
    else:
        offset = int(offset_str)
        
    return f"reg_p{page}_0x{offset:02X}"

def create_auto_band_freq_func(func_def):
    """
    根据 JSON 定义创建自动频段判断函数
    
    func_def 格式:
    {
        "type": "auto_band_freq",
        "extract": {"rf_ch_int": "x & 0xff", "rf_ch_frac": "..."},
        "freq_formula": "((rf_multi * rf_ch_int + ...) + 1) & 0xfffffffe",
        "bands": {
            "5G": {"rf_multi": 60000, "min": 5000000, "max": 6000000},
            "2G": {"rf_multi": 30000, "min": 2000000, "max": 3000000}
        }
    }
    """
    extract_exprs = func_def.get('extract', {})
    freq_formula = func_def.get('freq_formula', '')
    bands = func_def.get('bands', {})
    
    def auto_band_freq(x):
        # 计算提取变量
        local_vars = {'x': x, 'math': math}
        for var_name, expr in extract_exprs.items():
            local_vars[var_name] = eval(expr, {"__builtins__": None}, local_vars)
        
        # 尝试每个频段
        results = []
        for band_name, band_cfg in bands.items():
            rf_multi = band_cfg['rf_multi']
            freq_min = band_cfg['min']
            freq_max = band_cfg['max']
            
            # 计算频率
            calc_vars = {**local_vars, 'rf_multi': rf_multi}
            freq = eval(freq_formula, {"__builtins__": None}, calc_vars)
            
            if freq_min <= freq <= freq_max:
                return freq, band_name
            results.append((band_name, freq))
        
        # 无法确定频段，返回第一个计算值和调试信息
        if results:
            debug_info = ','.join([f"{b}={f}" for b, f in results])
            return results[0][1], f"??({debug_info})"
        return 0, "??"
    
    return auto_band_freq


def build_predefined_funcs(func_defs):
    """
    从 JSON 定义构建预定义函数表
    
    func_defs: JSON 中的 predefined_funcs 字典
    返回: {func_name: callable}
    """
    funcs = {}
    
    for name, definition in func_defs.items():
        if name.startswith('_'):  # 跳过注释字段
            continue
            
        func_type = definition.get('type', '')
        
        if func_type == 'auto_band_freq':
            funcs[name] = create_auto_band_freq_func(definition)
        elif func_type == 'transform':
            # 简单表达式类型
            expr = definition.get('expr', 'x')
            funcs[name] = lambda x, e=expr: eval(e, {"__builtins__": None, "math": math, "x": x})
    
    return funcs

def process_row(row, config_items, header_map, predefined_funcs=None):
    if predefined_funcs is None:
        predefined_funcs = {}
    new_row = {}
    # Copy existing fields
    for k, v in row.items():
        new_row[k] = v

    # Process configured items
    for item in config_items:
        reg_key = get_reg_key(item)
        
        if reg_key not in row:
            continue
            
        raw_val_str = row[reg_key]
        if not raw_val_str:
            continue
            
        try:
            if raw_val_str.startswith('0x'):
                raw_val = int(raw_val_str, 16)
            else:
                raw_val = int(raw_val_str)
        except ValueError:
            continue

        # If no post_process is defined, we might still want to output the value 
        # under its friendly name if it differs from the reg_key
        friendly_name = item.get('name')
        if friendly_name and friendly_name != reg_key:
            new_row[friendly_name] = raw_val

        pp = item.get('post_process')
        if not pp:
            continue

        # Handle Split
        if 'split' in pp:
            for split_item in pp['split']:
                name = split_item['name']
                msb, lsb = split_item['bit_range']
                mask = (1 << (msb - lsb + 1)) - 1
                val = (raw_val >> lsb) & mask
                new_row[name] = val

        # Handle Transform
        if 'transform' in pp:
            formula = pp['transform']
            # Safe eval context
            ctx = {'x': raw_val, 'math': math, 'log10': math.log10}
            try:
                val = eval(formula, {"__builtins__": None}, ctx)
                # Use the friendly name for the transformed value if possible, 
                # or append _processed
                target_name = friendly_name if friendly_name else f"{reg_key}_processed"
                new_row[target_name] = val
            except Exception as e:
                new_row[f"{friendly_name}_err"] = f"Error: {e}"

        # Handle Func
        if 'func' in pp:
            func_name = pp['func']
            if func_name in predefined_funcs:
                try:
                    res = predefined_funcs[func_name](raw_val)
                    target_name = friendly_name if friendly_name else f"{reg_key}_processed"
                    
                    if isinstance(res, tuple):
                        new_row[target_name] = res[0]
                        if len(res) > 1:
                            new_row[f"{target_name}_info"] = res[1]
                    else:
                        new_row[target_name] = res
                except Exception as e:
                    new_row[f"{friendly_name}_err"] = f"Error: {e}"

    return new_row

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 post_process.py <config.json> <input.csv> [output.csv]")
        sys.exit(1)

    config_path = sys.argv[1]
    input_csv = sys.argv[2]
    output_csv = sys.argv[3] if len(sys.argv) > 3 else "processed_trace.csv"

    # Load Config
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    predefined_funcs = build_predefined_funcs(config.get('predefined_funcs', {}))
    config_items = config.get('items', [])

    # Collect all new field names
    new_fields = []
    
    processed_fields = []
    for item in config_items:
        pp = item.get('post_process')
        friendly_name = item.get('name')
        
        if friendly_name:
            processed_fields.append(friendly_name)
        
        if pp:
            if 'split' in pp:
                for split_item in pp['split']:
                    processed_fields.append(split_item['name'])
            if 'transform' in pp:
                if not friendly_name:
                    processed_fields.append(f"{get_reg_key(item)}_processed")
            if 'func' in pp:
                target_name = friendly_name if friendly_name else f"{get_reg_key(item)}_processed"
                if not friendly_name:
                    processed_fields.append(target_name)
                # Check if it returns tuple (auto_band_freq)
                func_name = pp['func']
                func_def = config.get('predefined_funcs', {}).get(func_name)
                if func_def and func_def.get('type') == 'auto_band_freq':
                    processed_fields.append(f"{target_name}_info")

    # Process CSV
    with open(input_csv, 'r', newline='', encoding='utf-8') as f_in, \
         open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
        
        reader = csv.DictReader(f_in)
        
        # Determine output fields:
        # Append processed fields to the end
        fieldnames = reader.fieldnames + [f for f in processed_fields if f not in reader.fieldnames]
        
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)

        writer.writeheader()
        for row in reader:
            processed_row = process_row(row, config_items, {n: i for i, n in enumerate(reader.fieldnames)}, predefined_funcs)
            writer.writerow(processed_row)

    print(f"Processed data saved to {output_csv}")

if __name__ == "__main__":
    main()
