@echo off

:: Default flash to ota_0
espflash flash --monitor -T ./partitions.csv --erase-parts otadata %1 | tee esp32_output.log
::espflash flash --monitor -T ./partitions.csv %1 | tee esp32_output22.log

:: Flash to ota_1
::espflash flash --monitor -T ./partitions.csv --target-app-partition ota_1 %1