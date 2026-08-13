# Impossible Travel Detection

## MITRE ATT&CK
**Technique:** T1078 — Valid Accounts

## Objective
Identify potentially compromised accounts by detecting successful sign-ins from different countries where the calculated travel speed exceeds a realistic threshold.

## Data Source
* Microsoft Sentinel
* `SigninLogs`

## Detection Logic
The query:

1. Looks at successful sign-ins from the last **24 hours**.
2. Extracts the user's country, city, latitude, and longitude.
3. Compares consecutive sign-ins for the same user.
4. Identifies sign-ins originating from different countries.
5. Calculates the geographic distance between the two locations.
6. Calculates the time between the sign-ins.
7. Calculates the required travel speed.
8. Flags activity where the required speed exceeds **900 km/h**.

## KQL

```kql
let lookback = 24h;
let speedthresholdkmh = 900.0;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    Latitude = todouble(LocationDetails.geoCoordinates.latitude),
    Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    City,
    Country,
    Longitude,
    Latitude
| order by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend
    PrevUser = prev(UserPrincipalName),
    PrevTime = prev(TimeGenerated),
    PrevCountry = prev(Country),
    PrevCity = prev(City),
    PrevIP = prev(IPAddress),
    PrevLat = prev(Latitude),
    PrevLon = prev(Longitude)
| where UserPrincipalName == PrevUser
| where Country != PrevCountry
| extend
    DistanceKm = geo_distance_2points(
        PrevLon,
        PrevLat,
        Longitude,
        Latitude
    ) / 1000.0
| extend
    TravelHours = datetime_diff('minute', TimeGenerated, PrevTime) / 60.0
| where TravelHours > 0
| extend
    SpeedKmH = DistanceKm / TravelHours
| where SpeedKmH > speedthresholdkmh
| summarize arg_max(SpeedKmH, *) by UserPrincipalName
| project
    TimeGenerated,
    UserPrincipalName,
    PreviousLocation = strcat(PrevCity, ", ", PrevCountry),
    CurrentLocation = strcat(City, ", ", Country),
    PreviousIP = PrevIP,
    CurrentIP = IPAddress,
    DistanceKM = round(DistanceKm, 1),
    TravelHours = round(TravelHours, 2),
    SpeedKMh = round(SpeedKmH, 1)
| order by SpeedKMh desc
```

## Detection Example

```text
Successful Sign-in
        ↓
Same User
        ↓
Different Country
        ↓
Calculate Distance
        ↓
Calculate Travel Time
        ↓
Calculate Required Speed
        ↓
Speed > 900 km/h
        ↓
Potential Impossible Travel
```

## Example Output

| User                                        | Previous Location | Current Location | Distance | Travel Time | Required Speed |
| ------------------------------------------- | ----------------- | ---------------- | -------: | ----------: | -------------: |
| [user@company.com](mailto:user@company.com) | Delhi, India      | London, UK       | 6,700 km |       2 hrs |     3,350 km/h |

This activity would be flagged because the calculated travel speed exceeds the configured **900 km/h** threshold.

## False Positives

* Corporate VPNs
* Proxy services
* Cloud-based egress points
* Mobile networks
* Remote workers
* Shared accounts
* Incorrect IP geolocation

## Tuning

* Baseline normal user locations.
* Exclude known corporate VPN/proxy infrastructure.
* Adjust the speed threshold based on the environment.
* Correlate with device information and authentication methods.
* Review unfamiliar devices and applications.
* Consider MFA and Microsoft Entra sign-in risk.

## Investigation

When the detection triggers, investigate:

* Previous and current IP addresses
* Geographic locations
* Device information
* Authentication method
* MFA activity
* Sign-in risk
* User-agent information
* VPN/proxy usage
* Other suspicious activity associated with the account

## Related Techniques

* **T1078 — Valid Accounts**
* **T1078.004 — Valid Accounts: Cloud Accounts**
