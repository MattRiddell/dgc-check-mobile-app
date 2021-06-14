export const SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ec.europa.eu/dgc/DGC.schema.json",
  "title": "EU DGC",
  "description": "EU Digital Green Certificate",
  "required": [
    "ver",
    "nam",
    "dob"
  ],
  "type": "object",
  "properties": {
    "ver": {
      "title": "Schema version",
      "description": "Version of the schema, according to Semantic versioning (ISO, https://semver.org/ version 2.0.0 or newer)",
      "type": "string",
      "pattern": "^\\d+.\\d+.\\d+$",
      "examples": [
        "1.0.0"
      ]
    },
    "nam": {
      "description": "Surname(s), given name(s) - in that order",
      "$ref": "#/$defs/person_name"
    },
    "dob": {
      "title": "Date of birth",
      "description": "Date of Birth of the person addressed in the DGC. ISO 8601 date format restricted to range 1900-2099",
      "type": "string",
      "format": "date",
      "pattern": "[19|20][0-9][0-9]-(0[1-9]|1[0-2])-([0-2][1-9]|3[0|1])",
      "examples": [
        "1979-04-14"
      ]
    },
    "v": {
      "description": "Vaccination Group",
      "type": "array",
      "items": {
        "$ref": "#/$defs/vaccination_entry"
      },
      "minItems": 0
    },
    "t": {
      "description": "Test Group",
      "type": "array",
      "items": {
        "$ref": "#/$defs/test_entry"
      },
      "minItems": 0
    },
    "r": {
      "description": "Recovery Group",
      "type": "array",
      "items": {
        "$ref": "#/$defs/recovery_entry"
      },
      "minItems": 0
    }
  },
  "$defs": {
    "dose_posint": {
      "description": "Dose Number / Total doses in Series: positive integer, range: [1,9]",
      "type": "integer",
      "minimum": 1,
      "maximum": 9
    },
    "country_vt": {
      "description": "Country of Vaccination / Test, ISO 3166 where possible",
      "type": "string",
      "pattern": "[A-Z]{1,10}"
    },
    "issuer": {
      "description": "Certificate Issuer",
      "type": "string",
      "maxLength": 50
    },
    "person_name": {
      "description": "Person name: Surname(s), given name(s) - in that order",
      "required": [
        "fnt"
      ],
      "type": "object",
      "properties": {
        "fn": {
          "title": "Family name",
          "description": "The family or primary name(s) of the person addressed in the certificate",
          "type": "string",
          "maxLength": 50,
          "examples": [
            "d'Červenková Panklová"
          ]
        },
        "fnt": {
          "title": "Standardised family name",
          "description": "The family name(s) of the person transliterated",
          "type": "string",
          "pattern": "^[A-Z<]*$",
          "maxLength": 50,
          "examples": [
            "DCERVENKOVA<PANKLOVA"
          ]
        },
        "gn": {
          "title": "Given name",
          "description": "The given name(s) of the person addressed in the certificate",
          "type": "string",
          "maxLength": 50,
          "examples": [
            "Jiřina-Maria Alena"
          ]
        },
        "gnt": {
          "title": "Standardised given name",
          "description": "The given name(s) of the person transliterated",
          "type": "string",
          "pattern": "^[A-Z<]*$",
          "maxLength": 50,
          "$comment": "SematicSG: ICAO transliterated has max length of?",
          "examples": [
            "JIRINA<MARIA<ALENA"
          ]
        }
      }
    },
    "certificate_id": {
      "description": "Certificate Identifier, UVCI",
      "type": "string",
      "maxLength": 50
    },
    "vaccination_entry": {
      "description": "Vaccination Entry",
      "required": [
        "tg",
        "vp",
        "mp",
        "ma",
        "dn",
        "sd",
        "dt",
        "co",
        "is",
        "ci"
      ],
      "type": "object",
      "properties": {
        "tg": {
          "description": "disease or agent targeted",
          "$ref": "#/$defs/disease-agent-targeted"
        },
        "vp": {
          "description": "vaccine or prophylaxis",
          "$ref": "#/$defs/vaccine-prophylaxis"
        },
        "mp": {
          "description": "vaccine medicinal product",
          "$ref": "#/$defs/vaccine-medicinal-product"
        },
        "ma": {
          "description": "Marketing Authorization Holder - if no MAH present, then manufacturer",
          "$ref": "#/$defs/vaccine-mah-manf"
        },
        "dn": {
          "description": "Dose Number",
          "$ref": "#/$defs/dose_posint"
        },
        "sd": {
          "description": "Total Series of Doses",
          "$ref": "#/$defs/dose_posint"
        },
        "dt": {
          "description": "Date of Vaccination",
          "type": "string",
          "format": "date",
          "$comment": "SemanticSG: constrain to specific date range?"
        },
        "co": {
          "description": "Country of Vaccination",
          "$ref": "#/$defs/country_vt"
        },
        "is": {
          "description": "Certificate Issuer",
          "$ref": "#/$defs/issuer"
        },
        "ci": {
          "description": "Unique Certificate Identifier: UVCI",
          "$ref": "#/$defs/certificate_id"
        }
      }
    },
    "test_entry": {
      "description": "Test Entry",
      "required": [
        "tg",
        "tt",
        "sc",
        "tr",
        "tc",
        "co",
        "is",
        "ci"
      ],
      "type": "object",
      "properties": {
        "tg": {
          "$ref": "#/$defs/disease-agent-targeted"
        },
        "tt": {
          "description": "Type of Test",
          "type": "string"
        },
        "nm": {
          "description": "NAA Test Name",
          "type": "string"
        },
        "ma": {
          "description": "RAT Test name and manufacturer",
          "$ref": "#/$defs/test-manf"
        },
        "sc": {
          "description": "Date/Time of Sample Collection",
          "type": "string",
          "format": "date-time"
        },
        "dr": {
          "description": "Date/Time of Test Result",
          "type": "string",
          "format": "date-time"
        },
        "tr": {
          "description": "Test Result",
          "$ref": "#/$defs/test-result"
        },
        "tc": {
          "description": "Testing Centre",
          "type": "string",
          "maxLength": 50
        },
        "co": {
          "description": "Country of Test",
          "$ref": "#/$defs/country_vt"
        },
        "is": {
          "description": "Certificate Issuer",
          "$ref": "#/$defs/issuer"
        },
        "ci": {
          "description": "Unique Certificate Identifier, UVCI",
          "$ref": "#/$defs/certificate_id"
        }
      }
    },
    "recovery_entry": {
      "description": "Recovery Entry",
      "required": [
        "tg",
        "fr",
        "co",
        "is",
        "df",
        "du",
        "ci"
      ],
      "type": "object",
      "properties": {
        "tg": {
          "$ref": "#/$defs/disease-agent-targeted"
        },
        "fr": {
          "description": "ISO 8601 Date of First Positive Test Result",
          "type": "string",
          "format": "date"
        },
        "co": {
          "description": "Country of Test",
          "$ref": "#/$defs/country_vt"
        },
        "is": {
          "description": "Certificate Issuer",
          "$ref": "#/$defs/issuer"
        },
        "df": {
          "description": "ISO 8601 Date: Certificate Valid From",
          "type": "string",
          "format": "date"
        },
        "du": {
          "description": "Certificate Valid Until",
          "type": "string",
          "format": "date"
        },
        "ci": {
          "description": "Unique Certificate Identifier, UVCI",
          "$ref": "#/$defs/certificate_id"
        }
      }
    },
    "disease-agent-targeted": {
      "description": "EU eHealthNetwork: Value Sets for Digital Green Certificates. version 1.0, 2021-04-16, section 2.1",
      "type": "string",
      "enum": [
        "840539006"
      ]
    },
    "vaccine-prophylaxis": {
      "description": "EU eHealthNetwork: Value Sets for Digital Green Certificates. version 1.0, 2021-04-16, section 2.2",
      "type": "string",
      "enum": [
        "1119305005",
        "1119349007",
        "J07BX03"
      ]
    },
    "vaccine-medicinal-product": {
      "description": "EU eHealthNetwork: Value Sets for Digital Green Certificates. version 1.0, 2021-04-16, section 2.3",
      "type": "string",
      "enum": [
        "EU/1/20/1528",
        "EU/1/20/1507",
        "EU/1/21/1529",
        "EU/1/20/1525",
        "CVnCoV",
        "Sputnik-V",
        "Convidecia",
        "EpiVacCorona",
        "BBIBP-CorV",
        "Inactivated-SARS-CoV-2-Vero-Cell",
        "CoronaVac",
        "Covaxin"
      ]
    },
    "vaccine-mah-manf": {
      "description": "EU eHealthNetwork: Value Sets for Digital Green Certificates. version 1.0, 2021-04-16, section 2.4",
      "type": "string",
      "enum": [
        "ORG-100001699",
        "ORG-100030215",
        "ORG-100001417",
        "ORG-100031184",
        "ORG-100006270",
        "ORG-100013793",
        "ORG-100020693",
        "ORG-100010771",
        "ORG-100024420",
        "ORG-100032020",
        "Gamaleya-Research-Institute",
        "Vector-Institute",
        "Sinovac-Biotech",
        "Bharat-Biotech"
      ]
    },
    "test-manf": {
      "description": "EU eHealthNetwork: Value Sets for Digital Green Certificates. version 1.0, 2021-04-16, section 2.8",
      "type": "string",
      "enum": [
        "308",
        "344",
        "345",
        "768",
        "1097",
        "1114",
        "1144",
        "1162",
        "1173",
        "1180",
        "1190",
        "1199",
        "1215",
        "1218",
        "1223",
        "1225",
        "1232",
        "1236",
        "1244",
        "1246",
        "1253",
        "1256",
        "1263",
        "1266",
        "1267",
        "1268",
        "1271",
        "1278",
        "1295",
        "1296",
        "1304",
        "1319",
        "1331",
        "1333",
        "1341",
        "1343",
        "1360",
        "1363",
        "1365",
        "1375",
        "1392",
        "1420",
        "1437",
        "1443",
        "1456",
        "1466",
        "1468",
        "1481",
        "1484",
        "1489",
        "1490",
        "1574",
        "1604",
        "1606",
        "1654",
        "1736",
        "1747",
        "1763",
        "1764",
        "1767",
        "1769",
        "1815",
        "1822",
        "1833",
        "1844",
        "1870",
        "1884",
        "1906",
        "1919",
        "1934",
        "2010",
        "2017"
      ]
    },
    "test-result": {
      "description": "EU eHealthNetwork: Value Sets for Digital Green Certificates. version 1.0, 2021-04-16, section 2.9",
      "type": "string",
      "enum": [
        "260415000",
        "260373001"
      ]
    }
  }
}

