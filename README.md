# Syncurity Scan

De scanner achter [syncurity.nl](https://syncurity.nl): een gratis check van je
website, je e-mail en je domeinnaam. Honderd controles in tien onderdelen:

- **verbinding**: TLS 1.3, certificaat, https en HSTS
- **beveiliging en privacy**: beveiligingsheaders, trackers, verouderde software
- **e-mail**: DMARC, SPF, DKIM, MTA-STS, TLS-RPT en DANE
- **domeinnaam**: DNSSEC, CAA en nameservers
- **modern internet**: IPv6 en HTTP/3
- **vindbaar in Google** en **vindbaar voor AI**
- **snelheid**
- **vertrouwen en regels**: privacyverklaring, KvK-nummer en cookietoestemming
- **toegankelijkheid**

Elke uitslag staat in gewone taal: wat we zagen, en wat het betekent.

## Alleen kijken, nooit aankomen

De scan is **passief**. Hij kijkt alleen naar wat iedereen op internet kan zien:

- alleen poort 80 en 443 van de website, en DNS via een validerende resolver
- geen poortscan, geen inlogpogingen, geen verbinding met mailservers
- hooguit 60 verbindingen per scan
- vóór elke verbinding controleert de scanner of het adres echt publiek is,
  zodat niemand hem naar een intern netwerk kan sturen

## Wat erin zit

| Map | Wat |
|---|---|
| `keuring/` | de scanner: alle controles, de uitslag en de oplossingen per punt |
| `cmd/keur/` | de scan vanaf de opdrachtregel |
| `cmd/dienst/` | de webdienst (achter een reverse proxy): de scanpagina, het rapport en de pdf |
| `pdf/` | een klein pdf-pakket zonder afhankelijkheden |

Het portaal van syncurity.nl (inloggen en domeinbewijs) hoort hier niet bij.

## Zelf draaien

Nodig: Go (zie `go.mod` voor de versie).

```
go run ./cmd/keur voorbeeld.nl          # uitslag in de terminal
go run ./cmd/keur -json voorbeeld.nl    # als JSON
go test ./...
```

Scan alleen domeinen waarvoor je dat mag. Het volledige rapport (`-vol`) is
bedoeld voor je eigen domein.

## Na te bouwen

Onder elk rapport op syncurity.nl staat met welke versie het gemaakt is. Met
dezelfde commit en dezelfde Go-versie bouw je precies hetzelfde programma:

```
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -ldflags "-s -w -X main.versie=<commit>" -o syncurity-keuring ./cmd/dienst
sha256sum syncurity-keuring
```

## Lijsten van anderen

Voor verouderde software gebruikt de scan twee lijsten. Ze zitten in het
programma, zodat de dienst zelf niets ophaalt. Herkomst en licentie staan in
[`keuring/data/HERKOMST.txt`](keuring/data/HERKOMST.txt).

## Licentie

[GNU Affero General Public License v3.0](LICENSE). Draai je een aangepaste
versie als dienst voor anderen, dan deel je ook je wijzigingen.

## Beveiliging

Een lek gevonden? Meld het niet in een issue, maar volgens
[SECURITY.md](SECURITY.md).

---

## In English

The scanner behind [syncurity.nl](https://syncurity.nl): a free, passive check
of a website, its e-mail and its domain name, with 100 checks in ten groups,
explained in plain Dutch. It only looks at what is public (ports 80 and 443,
DNS via a validating resolver), never scans ports, never tries to log in and
never connects to mail servers. Licensed under the AGPL-3.0. Report security
issues as described in [SECURITY.md](SECURITY.md). Contributions are welcome
in Dutch or English; see [CONTRIBUTING.md](CONTRIBUTING.md).
