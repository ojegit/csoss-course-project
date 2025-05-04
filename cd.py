

###########################################################
# Tested with python 3.12
# tensorflow 2.18.0 (as of writing this the latest version 2.19.0 did not work)
# pandas 2.2.3
# numpy 2.0.2
# scikit-learn 1.6.1
# joblib 1.4.2
###########################################################


import os
import time
import datetime
import subprocess
import argparse
import pandas as pd
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import joblib

### CONSTANTS 

#path to keras model, extension .keras
model_path = None #path to model e.g ./CIC_IDS2018/cic_ids2018_friday.keras

#path to sciki-learn scaler, extension .pkl
scaler_path = None #path to scaler e.g ./CIC_IDS2018/scaler.pkl

#path to dumpcap.exe
dumpcap_exe = None #path to dumpcap.exe

#working directory of the cfm.bat file 
cfm_bat_cwd = None #CICFLowMeter-4.0 cfm.mat working folder i.e CICFlowMeter-4.0\bin

#columns that are dropped from the flow (.csv) file
drop_flow_columns = ['Src Port', 'Src IP', 'Dst IP', 'Timestamp', 'Label', 'Flow ID', 'Flow Byts/s', 'Flow Pkts/s']


### FUNCTIONS

#parsing the duration CLI input
def parse_duration(duration_str):
    """Parses a duration string like '10s', '5m', '2h', '1.5d' into seconds."""
    if duration_str is None:
        return None
    units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    try:
        unit = duration_str[-1].lower()
        if unit not in units:
            raise ValueError(f"Unknown time unit '{unit}'. Use one of: s, m, h, d.")
        value = float(duration_str[:-1])
        if value < 0:
            raise ValueError("Duration must be non-negative.")
        return value * units[unit]
    except (ValueError, IndexError):
        raise argparse.ArgumentTypeError(
            f"Invalid duration format: '{duration_str}'. Use format like 30s, 5m, 2.5h, 1d."
        )

#capturing traffic with dumpcap.exe
def capture_pcap(interface, duration_sec, filename, verbose=0):
    command = [dumpcap_exe, '-i', interface, '-a', f'duration:{int(duration_sec)}', '-w', filename, '-P']
    result = subprocess.run(command, creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True, text=True)
    if verbose > 0:
        print(result.stdout)
    return filename


#convert packet files to flows
def convert_to_flow(input_filename, drop_columns=None, verbose=0):
    input_filename = os.path.abspath(input_filename) #absolute paths
    command = ["cfm.bat", input_filename, os.path.dirname(input_filename)]
    result = subprocess.run(command, cwd=cfm_bat_cwd, capture_output=True, text=True, shell=True)
    if drop_columns is not None:
        df = pd.read_csv(input_filename + '_Flow.csv')
        df.drop(columns=drop_columns, inplace=True)
        df.to_csv(input_filename + '_Flow.csv', index=False)
        if verbose > 0:
            print(f'Dropped columns: {drop_columns}')
    if verbose > 0:
        print(result.stdout)

#load scikit-learn scaler from file
def load_scaler():
    return joblib.load(scaler_path)


#load keras model from file
def load_model():
    return tf.keras.models.load_model(model_path)


#predict with keras model
def predict_intrusion_label(model, scaler, input_filename, drop_columns=None, log_name='log_file.log', verbose=0):
    test_data = pd.read_csv(input_filename)
    if drop_columns is not None:
        test_data.drop(columns=drop_columns, inplace=True)
    predictions = model.predict(scaler.transform(test_data), verbose=verbose)
    return predictions.flatten()

### MAIN

# CLI
def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection CLI Tool")
    parser.add_argument('--interval', type=int, default=5, help='Capture interval in seconds')
    parser.add_argument('--interface', type=str, help='Network interface ID (from dumpcap.exe -D)')
    parser.add_argument('--log', type=str, default='./intrusion_log.txt', help='Path to the output log file')
    parser.add_argument('--output-dir', type=str, default='./', help='Directory to save temporary files')
    parser.add_argument('--duration', type=str, default=None, help='How long to run (e.g., 30s, 5m, 2h, 1d)')
    parser.add_argument('--dry-run', action='store_true', help="Validate config and dependencies without running the main loop")
    parser.add_argument('--test-input', type=str, help='Path to a pre-converted flow CSV or pcap file (test phase only)')
    args = parser.parse_args()

    # Parse duration if provided
    duration_limit = parse_duration(args.duration)
    tmp_pcap = 'tmp.pcap'
    start_time_total = time.time()

    # If in dry-run mode, just check dependencies and args
    if args.dry_run:
        print("=== Dry Run Mode ===")
        print(f"Interface        : {args.interface}")
        print(f"Capture Interval : {args.interval} seconds")
        print(f"Duration         : {args.duration} → {duration_limit} seconds" if args.duration else "Duration         : Unlimited")
        print(f"Log File         : {args.log}")
        print(f"Output Directory : {args.output_dir}")

        print("\nChecking dependencies...")
        print(f"{'✓' if os.path.exists(dumpcap_exe) else '✗'} dumpcap.exe at: {dumpcap_exe}")
        cfm_bat_path = os.path.join(cfm_bat_cwd, "cfm.bat")
        print(f"{'✓' if os.path.exists(cfm_bat_path) else '✗'} cfm.bat at: {cfm_bat_path}")

        try:
            _ = load_model()
            print("✓ Model loaded successfully.")
        except Exception as e:
            print(f"✗ Failed to load model: {e}")

        try:
            _ = load_scaler()
            print("✓ Scaler loaded successfully.")
        except Exception as e:
            print(f"✗ Failed to load scaler: {e}")

        print("\nDry run complete.")
        return

    # If test input is provided, bypass the capture loop
    if args.test_input:
        scaler = load_scaler()
        model = load_model()
        
        if args.test_input.endswith('.csv'):
            print(f"[*] Predicting labels from pre-converted flow CSV: {args.test_input}")
            prediction = predict_intrusion_label(model, scaler, args.test_input)
            for i, proba in enumerate(prediction):
                label = 'BENIGN' if proba < 0.5 else 'ATTACK'
                ts1 = datetime.datetime.now()
                ts2 = int(ts1.timestamp() * 1000)
                print(f"id: {i+1}, timestamp: {ts1}, label: {label}")
        elif args.test_input.endswith('.pcap'):
            print(f"[*] Converting pcap file to flows: {args.test_input}")
            convert_to_flow(args.test_input)
            prediction = predict_intrusion_label(model, scaler, args.test_input + '_Flow.csv')
            for i, proba in enumerate(prediction):
                label = 'BENIGN' if proba < 0.5 else 'ATTACK'
                ts1 = datetime.datetime.now()
                ts2 = int(ts1.timestamp() * 1000)
                print(f"id: {i+1}, timestamp: {ts1}, label: {label}")
        else:
            print(f"[*] Invalid file format for --test-input: {args.test_input}. Please provide a .csv or .pcap file.")
        return

    # If running normally, create the log file if it doesn't exist
    if not os.path.exists(args.log):
        print("Logfile doesn't exist. Creating it...")
        with open(args.log, 'w', encoding='utf-8') as f:
            f.write('ID,TIMESTAMP,LABEL\n')

    # Normal operation for monitoring and capturing traffic
    with open(args.log, 'a', encoding='utf-8') as log_file:
        try:
            i = 1
            scaler = load_scaler()
            model = load_model()
            print("Started intrusion detection...")

            while True:
                if duration_limit is not None and (time.time() - start_time_total) >= duration_limit:
                    print("Reached time limit. Exiting.")
                    break

                t_start = time.time()
                print(f"[*] Capturing traffic for {args.interval} secs...")
                pcap_file = capture_pcap(args.interface, args.interval, os.path.join(args.output_dir, tmp_pcap))
                print("[*] Converting to flows...")
                convert_to_flow(pcap_file, drop_columns = drop_flow_columns)
                print("[*] Predicting labels...")
                prediction = predict_intrusion_label(model, scaler, pcap_file + '_Flow.csv')

                for j, proba in enumerate(prediction):
                    label = 'BENIGN' if proba < 0.5 else 'ATTACK'
                    ts1 = datetime.datetime.now()
                    ts2 = int(ts1.timestamp() * 1000)
                    print(f"id: {j+i}, timestamp: {ts1}, label: {label}")
                    log_file.write(f"{j+i},{ts2},{label}\n") # add to log

                print(f"Cycle done in {time.time() - t_start:.2f} seconds\n{'-'*40}")
                i += len(prediction)
        except Exception as e:
            print("An exception occurred:", e)
        finally:
            print("Terminated.")

if __name__ == '__main__':
    main()    
