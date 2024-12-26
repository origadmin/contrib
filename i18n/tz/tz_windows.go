/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package tz implements the functions, types, and interfaces for the module.
package tz

import (
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/origadmin/toolkits/codec"
)

//go:embed map_zones.json
var jsonMapZones []byte

//| **Time Zone Name**                                           | **TimeZoneID**                  |
//| ------------------------------------------------------------ | ------------------------------- |
//| (UTC-12:00) International Date Line West                     | Dateline Standard Time          |
//| (UTC-11:00) Coordinated Universal Time-11                    | UTC-11                          |
//| (UTC-10:00) Aleutian Islands                                 | Aleutian Standard Time          |
//| (UTC-10:00) Hawaii                                           | Hawaiian Standard Time          |
//| (UTC-09:30) Marquesas Islands                                | Marquesas Standard Time         |
//| (UTC-09:00) Alaska                                           | Alaskan Standard Time           |
//| (UTC-09:00) Coordinated Universal Time-09                    | UTC-09                          |
//| (UTC-08:00) Baja California                                  | Pacific Standard Time (Mexico)  |
//| (UTC-08:00) Coordinated Universal Time-08                    | UTC-08                          |
//| (UTC-08:00) Pacific Time (US & Canada)                       | Pacific Standard Time           |
//| (UTC-07:00) Arizona                                          | US Mountain Standard Time       |
//| (UTC-07:00) Chihuahua, La Paz, Mazatlan                      | Mountain Standard Time (Mexico) |
//| (UTC-07:00) Mountain Time (US & Canada)                      | Mountain Standard Time          |
//| (UTC-07:00) Yukon                                            | Yukon Standard Time             |
//| (UTC-06:00) Central America                                  | Central America Standard Time   |
//| (UTC-06:00) Central Time (US & Canada)                       | Central Standard Time           |
//| (UTC-06:00) Easter Island                                    | Easter Island Standard Time     |
//| (UTC-06:00) Guadalajara, Mexico City, Monterrey              | Central Standard Time (Mexico)  |
//| (UTC-06:00) Saskatchewan                                     | Canada Central Standard Time    |
//| (UTC-05:00) Bogota, Lima, Quito, Rio Branco                  | SA Pacific Standard Time        |
//| (UTC-05:00) Chetumal                                         | Eastern Standard Time (Mexico)  |
//| (UTC-05:00) Eastern Time (US & Canada)                       | Eastern Standard Time           |
//| (UTC-05:00) Haiti                                            | Haiti Standard Time             |
//| (UTC-05:00) Havana                                           | Cuba Standard Time              |
//| (UTC-05:00) Indiana (East)                                   | US Eastern Standard Time        |
//| (UTC-05:00) Turks and Caicos                                 | Turks And Caicos Standard Time  |
//| (UTC-04:00) Asuncion                                         | Paraguay Standard Time          |
//| (UTC-04:00) Atlantic Time (Canada)                           | Atlantic Standard Time          |
//| (UTC-04:00) Caracas                                          | Venezuela Standard Time         |
//| (UTC-04:00) Cuiaba                                           | Central Brazilian Standard Time |
//| (UTC-04:00) Georgetown, La Paz, Manaus, San Juan             | SA Western Standard Time        |
//| (UTC-04:00) Santiago                                         | Pacific SA Standard Time        |
//| (UTC-03:30) Newfoundland                                     | Newfoundland Standard Time      |
//| (UTC-03:00) Araguaina                                        | Tocantins Standard Time         |
//| (UTC-03:00) Brasilia                                         | E. South America Standard Time  |
//| (UTC-03:00) Cayenne, Fortaleza                               | SA Eastern Standard Time        |
//| (UTC-03:00) City of Buenos Aires                             | Argentina Standard Time         |
//| (UTC-03:00) Greenland                                        | Greenland Standard Time         |
//| (UTC-03:00) Montevideo                                       | Montevideo Standard Time        |
//| (UTC-03:00) Punta Arenas                                     | Magallanes Standard Time        |
//| (UTC-03:00) Saint Pierre and Miquelon                        | Saint Pierre Standard Time      |
//| (UTC-03:00) Salvador                                         | Bahia Standard Time             |
//| (UTC-02:00) Coordinated Universal Time-02                    | UTC-02                          |
//| (UTC-01:00) Azores                                           | Azores Standard Time            |
//| (UTC-01:00) Cabo Verde Is.                                   | Cape Verde Standard Time        |
//| (UTC) Coordinated Universal Time                             | UTC                             |
//| (UTC+00:00) Dublin, Edinburgh, Lisbon, London                | GMT Standard Time               |
//| (UTC+00:00) Monrovia, Reykjavik                              | Greenwich Standard Time         |
//| (UTC+00:00) Sao Tome                                         | Sao Tome Standard Time          |
//| (UTC+01:00) Casablanca                                       | Morocco Standard Time           |
//| (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna | W. Europe Standard Time         |
//| (UTC+01:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague | Central Europe Standard Time    |
//| (UTC+01:00) Brussels, Copenhagen, Madrid, Paris              | Romance Standard Time           |
//| (UTC+01:00) Sarajevo, Skopje, Warsaw, Zagreb                 | Central European Standard Time  |
//| (UTC+01:00) West Central Africa                              | W. Central Africa Standard Time |
//| (UTC+02:00) Amman                                            | Jordan Standard Time            |
//| (UTC+02:00) Athens, Bucharest                                | GTB Standard Time               |
//| (UTC+02:00) Beirut                                           | Middle East Standard Time       |
//| (UTC+02:00) Cairo                                            | Egypt Standard Time             |
//| (UTC+02:00) Chisinau                                         | E. Europe Standard Time         |
//| (UTC+02:00) Damascus                                         | Syria Standard Time             |
//| (UTC+02:00) Gaza, Hebron                                     | West Bank Standard Time         |
//| (UTC+02:00) Harare, Pretoria                                 | South Africa Standard Time      |
//| (UTC+02:00) Helsinki, Kyiv, Riga, Sofia, Tallinn, Vilnius    | FLE Standard Time               |
//| (UTC+02:00) Jerusalem                                        | Israel Standard Time            |
//| (UTC+02:00) Kaliningrad                                      | Kaliningrad Standard Time       |
//| (UTC+02:00) Khartoum                                         | Sudan Standard Time             |
//| (UTC+02:00) Tripoli                                          | Libya Standard Time             |
//| (UTC+02:00) Windhoek                                         | Namibia Standard Time           |
//| (UTC+03:00) Baghdad                                          | Arabic Standard Time            |
//| (UTC+03:00) Istanbul                                         | Turkey Standard Time            |
//| (UTC+03:00) Kuwait, Riyadh                                   | Arab Standard Time              |
//| (UTC+03:00) Minsk                                            | Belarus Standard Time           |
//| (UTC+03:00) Moscow, St. Petersburg                           | Russian Standard Time           |
//| (UTC+03:00) Nairobi                                          | E. Africa Standard Time         |
//| (UTC+03:30) Tehran                                           | Iran Standard Time              |
//| (UTC+04:00) Abu Dhabi, Muscat                                | Arabian Standard Time           |
//| (UTC+04:00) Astrakhan, Ulyanovsk                             | Astrakhan Standard Time         |
//| (UTC+04:00) Baku                                             | Azerbaijan Standard Time        |
//| (UTC+04:00) Izhevsk, Samara                                  | Russia Time Zone 3              |
//| (UTC+04:00) Port Louis                                       | Mauritius Standard Time         |
//| (UTC+04:00) Saratov                                          | Saratov Standard Time           |
//| (UTC+04:00) Tbilisi                                          | Georgian Standard Time          |
//| (UTC+04:00) Volgograd                                        | Volgograd Standard Time         |
//| (UTC+04:00) Yerevan                                          | Caucasus Standard Time          |
//| (UTC+04:30) Kabul                                            | Afghanistan Standard Time       |
//| (UTC+05:00) Ashgabat, Tashkent                               | West Asia Standard Time         |
//| (UTC+05:00) Ekaterinburg                                     | Ekaterinburg Standard Time      |
//| (UTC+05:00) Islamabad, Karachi                               | Pakistan Standard Time          |
//| (UTC+05:00) Qyzylorda                                        | Qyzylorda Standard Time         |
//| (UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi              | India Standard Time             |
//| (UTC+05:30) Sri Jayawardenepura                              | Sri Lanka Standard Time         |
//| (UTC+05:45) Kathmandu                                        | Nepal Standard Time             |
//| (UTC+06:00) Astana                                           | Central Asia Standard Time      |
//| (UTC+06:00) Dhaka                                            | Bangladesh Standard Time        |
//| (UTC+06:00) Omsk                                             | Omsk Standard Time              |
//| (UTC+06:30) Yangon (Rangoon)                                 | Myanmar Standard Time           |
//| (UTC+07:00) Bangkok, Hanoi, Jakarta                          | SE Asia Standard Time           |
//| (UTC+07:00) Barnaul, Gorno-Altaysk                           | Altai Standard Time             |
//| (UTC+07:00) Hovd                                             | W. Mongolia Standard Time       |
//| (UTC+07:00) Krasnoyarsk                                      | North Asia Standard Time        |
//| (UTC+07:00) Novosibirsk                                      | N. Central Asia Standard Time   |
//| (UTC+07:00) Tomsk                                            | Tomsk Standard Time             |
//| (UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi            | China Standard Time             |
//| (UTC+08:00) Irkutsk                                          | North Asia East Standard Time   |
//| (UTC+08:00) Kuala Lumpur, Singapore                          | Singapore Standard Time         |
//| (UTC+08:00) Perth                                            | W. Australia Standard Time      |
//| (UTC+08:00) Taipei                                           | Taipei Standard Time            |
//| (UTC+08:00) Ulaanbaatar                                      | Ulaanbaatar Standard Time       |
//| (UTC+08:45) Eucla                                            | Aus Central W. Standard Time    |
//| (UTC+09:00) Chita                                            | Transbaikal Standard Time       |
//| (UTC+09:00) Osaka, Sapporo, Tokyo                            | Tokyo Standard Time             |
//| (UTC+09:00) Pyongyang                                        | North Korea Standard Time       |
//| (UTC+09:00) Seoul                                            | Korea Standard Time             |
//| (UTC+09:00) Yakutsk                                          | Yakutsk Standard Time           |
//| (UTC+09:30) Adelaide                                         | Cen. Australia Standard Time    |
//| (UTC+09:30) Darwin                                           | AUS Central Standard Time       |
//| (UTC+10:00) Brisbane                                         | E. Australia Standard Time      |
//| (UTC+10:00) Canberra, Melbourne, Sydney                      | AUS Eastern Standard Time       |
//| (UTC+10:00) Guam, Port Moresby                               | West Pacific Standard Time      |
//| (UTC+10:00) Hobart                                           | Tasmania Standard Time          |
//| (UTC+10:00) Vladivostok                                      | Vladivostok Standard Time       |
//| (UTC+10:30) Lord Howe Island                                 | Lord Howe Standard Time         |
//| (UTC+11:00) Bougainville Island                              | Bougainville Standard Time      |
//| (UTC+11:00) Chokurdakh                                       | Russia Time Zone 10             |
//| (UTC+11:00) Magadan                                          | Magadan Standard Time           |
//| (UTC+11:00) Norfolk Island                                   | Norfolk Standard Time           |
//| (UTC+11:00) Sakhalin                                         | Sakhalin Standard Time          |
//| (UTC+11:00) Solomon Is., New Caledonia                       | Central Pacific Standard Time   |
//| (UTC+12:00) Anadyr, Petropavlovsk-Kamchatsky                 | Russia Time Zone 11             |
//| (UTC+12:00) Auckland, Wellington                             | New Zealand Standard Time       |
//| (UTC+12:00) Coordinated Universal Time+12                    | UTC+12                          |
//| (UTC+12:00) Fiji                                             | Fiji Standard Time              |
//| (UTC+12:45) Chatham Islands                                  | Chatham Islands Standard Time   |
//| (UTC+13:00) Coordinated Universal Time+13                    | UTC+13                          |
//| (UTC+13:00) Nuku’alofa                                       | Tonga Standard Time             |
//| (UTC+13:00) Samoa                                            | Samoa Standard Time             |
//| (UTC+14:00) Kiritimati Island                                | Line Islands Standard Time      |

// TimeZoneMap Time Zone Map
type TimeZoneMap struct {
	ZoneID    string   `json:"zone_id"`
	TimeZones []string `json:"time_zones"`
}

// mapZones Time Zone IDs
var mapZones []TimeZoneMap

func init() {
	err := json.Unmarshal(jsonMapZones, &mapZones)
	if err != nil {
		return
	}
}

type MapZone struct {
	Other     string   `json:"other" xml:"other,attr"`
	Territory string   `json:"territory" xml:"territory,attr"`
	Type      string   `json:"-" xml:"type,attr"`
	Types     []string `json:"types" xml:"-"`
}

type MapTimeZones struct {
	OtherVersion string    `json:"other_version" xml:"otherVersion,attr"`
	TypeVersion  string    `json:"type_version" xml:"typeVersion,attr"`
	MapZone      []MapZone `json:"map_zone" xml:"mapZone"`
}

type WindowsZones struct {
	MapTimeZones MapTimeZones `json:"map_timezones" xml:"mapTimezones"`
}

type SupplementalData struct {
	Version struct {
		Number string `json:"number" xml:"number,attr"`
	} `json:"version" xml:"version"`
	WindowsZones WindowsZones `json:"windows_zones" xml:"windowsZones"`
}

func WindowsZonesFromJSON(filePath string) (WindowsZones, error) {
	var supplementalData SupplementalData
	err := codec.DecodeFromFile(filePath, &supplementalData)
	if err != nil {
		return WindowsZones{}, err
	}
	return supplementalData.WindowsZones, nil
}

func WindowsZonesFromXMLToJSON(filePath string) error {
	var supplementalData SupplementalData
	err := codec.DecodeFromFile(filePath, &supplementalData)
	if err != nil {
		return err
	}
	supplementalData.WindowsZones.MapTimeZones.MapZone = splitWindowsZoneType(supplementalData.WindowsZones.MapTimeZones.MapZone)
	if err := codec.EncodeToFile("windows/windows_zones.json", supplementalData); err != nil {
		return err
	}

	return nil
}

func splitWindowsZoneType(mz []MapZone) []MapZone {
	var tz []MapZone
	for i := range mz {
		mz[i].Types = strings.Split(mz[i].Type, " ")
	}
	return tz
}

func FixTimeZoneFromWindowsZones(windowsZones WindowsZones) []TimeZone {
	var timeZones []TimeZone
	mapZones := windowsZones.MapTimeZones.MapZone
	for i := range TimeZones {
		timeZones = append(timeZones, fixWindowsZoneType(mapZones, TimeZones[i]))
	}
	return timeZones
}

func TimeZoneToTimeZoneMap(mapfile string) {
	m := make(map[string]TimeZoneMap)
	for i := range TimeZones {
		if TimeZones[i].ZoneID == "" {
			continue
		}
		if zone, ok := m[TimeZones[i].ZoneID]; ok {
			if !contains(zone.TimeZones, TimeZones[i].ZoneName) {
				zone.TimeZones = append(zone.TimeZones, TimeZones[i].ZoneName)
				m[TimeZones[i].ZoneID] = zone
			}
		} else {
			m[TimeZones[i].ZoneID] = TimeZoneMap{
				ZoneID:    TimeZones[i].ZoneID,
				TimeZones: []string{TimeZones[i].ZoneName},
			}
		}
	}
	var zoneMaps []TimeZoneMap
	for _, zoneMap := range m {
		zoneMaps = append(zoneMaps, zoneMap)
	}
	bytes, err := json.MarshalIndent(zoneMaps, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(mapfile, bytes, 0644)
}

func SaveNewTimeZonesToJSON(timeZones []TimeZone) error {
	bytes, err := json.MarshalIndent(&timeZones, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("time_zone.json", bytes, 0644)
}

func fixWindowsZoneType(mz []MapZone, tz TimeZone) TimeZone {
	for i := range mz {
		if contains(mz[i].Types, tz.ZoneName) && mz[i].Territory == tz.CountryCode {
			tz.ZoneID = mz[i].Other
		}
	}
	return tz
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func location() string {
	path, err := exec.LookPath("tzutil")
	if err != nil {
		return defaultTimeZone
	}
	cmd := exec.Command(path, "/g")
	out, err := cmd.Output()
	if err != nil {
		return defaultTimeZone
	}
	zone := strings.Trim(string(out), "\r\n")
	for i := range mapZones {
		if mapZones[i].ZoneID == zone {
			return mapZones[i].TimeZones[len(mapZones[i].TimeZones)-1]
		}
	}
	return defaultTimeZone
}
