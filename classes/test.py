import re
dateAndPattern = re.compile(r"(?:and )?(?:date (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)) to (?:[0-9]|0[1-9]|[12][0-9]|3[01])-(?:[0-9]|0[1-9]|1[012])-(?:19\d\d|20\d\d)(?: and)?")

filterStr = "zeuygduy date 11-11-2000 to 11-11-2000"

dateAndList = re.findall(dateAndPattern, filterStr)

print(dateAndList)