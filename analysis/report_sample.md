# Sample Report (Synthetic Demo)

Student: <your name>
Date: <date>

## Scope
Analyze bundled synthetic samples using the provided UI. No external samples.

## Static Analysis Highlights
- sim_print.py contains string "SIM_PRINT" and prints a benign message.

## Dynamic Analysis Highlights
- sim_dropper creates sandbox_output/dropped.txt with benign content.
- sim_netclient connects to localhost sink and logs a short message.

## YARA
- Rules match on embedded SIM_* markers only.

## Conclusion
All samples are benign and for education only. No malware present.
