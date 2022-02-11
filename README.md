# LMAlertsToCSV

This script will output a CSV when run locally. 

When the script is run, it will prompt you for the API access ID/key. This user needs to at least have access to view resources and manage reports. The company URL must be input as well. 

The script will then ask you for the number of days you want alerts for (max 30). It will then create the reports in LogicMonitor (1 for each day going back the amt of days you specify). It will then read the reports one at a time and add them to a master list.

The master list of all alerts for the amt of days you specify will be output as a local CSV file named "alertListv3"
