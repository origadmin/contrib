# I18n

## 1. Get tzdata from https://data.iana.org

### 1.1 Download tzdata from https://data.iana.org

```bash
mkdir tzdb
cd tzdb
wget https://www.iana.org/time-zones/repository/tzcode-latest.tar.gz
wget https://www.iana.org/time-zones/repository/tzdata-latest.tar.gz
gzip -dc tzcode-latest.tar.gz | tar -xf -
gzip -dc tzdata-latest.tar.gz | tar -xf -
```

### 1.2 Download tzdata from https://timezonedb.com

```bash
wget https://timezonedb.com/files/TimeZoneDB.csv.zip -O TimeZoneDB.csv.zip
zip -d TimeZoneDB.csv.zip
```

### 1.3 Download ldmlSupplemental.dtd from https://github.com/unicode-org/cldr/blob/main/common/dtd/ldmlSupplemental.dtd

### 1.4 Download windowsZones.xml from https://github.com/unicode-org/cldr/blob/main/common/supplemental/windowsZones.xml
