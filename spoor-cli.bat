@echo off
rem Command-line use, for example:  spoor-cli status "My case"   or   spoor-cli run "My case" --no-llm
"%~dp0runtime\python\python.exe" -m spoor %*
