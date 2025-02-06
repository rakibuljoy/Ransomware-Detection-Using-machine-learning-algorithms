import json

metadata = {
    "DebugSize": "0",
    "DebugRVA": "0",
    "MajorImageVersion": "0",
    "MajorOSVersion": "0",
    "ExportRVA": "0",
    "ExportSize": "0",
    "IatVRA": "0",
    "MajorLinkerVersion": "14",
    "MinorLinkerVersion": "33",
    "NumberOfSections": "7",
    "SizeOfStackReserve": "1048576",
    "DllCharacteristics": "49504",
    "ResourceSize": "624640",
    "BitcoinAddresses": "0",
   
}


output_file = "metadata.json"
with open(output_file, "w") as json_file:
    json.dump(metadata, json_file, indent=4)

print(f"Metadata saved to {output_file}")
