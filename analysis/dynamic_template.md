# Dynamic Analysis Template

Samples: sim_dropper.c (compiled to compiled/sim_dropper), sim_netclient.py

Environment:
- Worker container with network disabled globally; localhost-only for sink
- Timeout: 10s; Non-root user

Observations:
- sim_dropper: creates sandbox_output/dropped.txt with benign text
- sim_netclient: connects to 127.0.0.1:9009 and sends a short message

Artifacts:
- sandbox_output/dropped.txt
- run logs in logs/run_history.log
- captured_messages.log with network message

Notes:
- All actions are synthetic and local-only.
