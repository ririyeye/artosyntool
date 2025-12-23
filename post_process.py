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

def process_row(row, config_items, header_map):
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

    config_items = config.get('items', [])

    # Collect all new field names
    new_fields = []
    
    processed_fields = []
    for item in config_items:
        pp = item.get('post_process')
        friendly_name = item.get('name')
        
        if pp:
            if 'split' in pp:
                for split_item in pp['split']:
                    processed_fields.append(split_item['name'])
            if 'transform' in pp:
                processed_fields.append(friendly_name if friendly_name else f"{get_reg_key(item)}_processed")
        else:
            if friendly_name:
                processed_fields.append(friendly_name)

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
            processed_row = process_row(row, config_items, {n: i for i, n in enumerate(reader.fieldnames)})
            writer.writerow(processed_row)

    print(f"Processed data saved to {output_csv}")

if __name__ == "__main__":
    main()
