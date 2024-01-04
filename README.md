# fshipy-dev
## fixes and updates
1) Added chunking.
2) Added mutltithreading.
3) Added better logging system.
4) Added position points for log continuation.
5) Daily Log rotation
6) feature to show how much log are processed
7) debug level logging which shows problematic logs that were not parsed.
8) fixed regex escape for windows logs.

## Need to do:
1) Problems and issue related to pointer rotation
2) daemon as a python service not as a linux service (Daemon as a linux service is buggy for this as it uses mutlithreading so it will not get killed instead only 1 instance will be killed.)
