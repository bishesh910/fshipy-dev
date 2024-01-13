# fshipy-dev
## fixes and updates
1) Added chunking.
2) Added mutltithreading.
3) Added better logging system.
4) Added position points for log continuation.
5) Daily Log rotation
6) feature to show how much log are processed
7) debug level logging which shows problematic logs that were not parsed.
8) used ijson module which is much better than json module for handling data.

## Need to do:
2) daemon as a python service not as a linux service (Daemon as a linux service is buggy for this as it uses mutlithreading so it will not get killed instead only 1 instance will be killed.)
3) stress test this shipper.
4) issue with list used to collect chunks of json as it only stores some amount of logs.
