# NHTSA recall fixtures

Unmodified responses from the NHTSA recalls API, retrieved 2026-10-29:

- `recalls_mazda6_2018.json` and `recalls_mazda6_2019.json`: HTTP 200 for
  `https://api.nhtsa.gov/recalls/recallsByVehicle?make=MAZDA&model=MAZDA6&modelYear=2018`
  (and `2019`).
- `recalls_mazda6_2021_http400.json`: the HTTP 400 body returned for 2021 (and
  2020), which reports zero results.

Source: US National Highway Traffic Safety Administration. NHTSA's Terms of Use
(https://www.nhtsa.gov/about-nhtsa/terms-use) describe site information as public
information that may be distributed or copied, without accuracy warranty. These
files are test inputs only and are not a current recall check.
