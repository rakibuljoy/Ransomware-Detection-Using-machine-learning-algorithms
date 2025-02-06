import os
import pefile

def extract_features(pe_path):
  
    if not os.path.exists(pe_path):
        print(f"Error: The file {pe_path} does not exist.")
        return None


    if os.path.getsize(pe_path) == 0:
        print(f"Error: The file {pe_path} is empty.")
        return None

    try:
       
        if not os.access(pe_path, os.R_OK):
            print(f"Error: No read access to file {pe_path}.")
            return None

        print(f"Processing file: {pe_path}")

        pe = pefile.PE(pe_path)

    
        def get_pe_attribute(pe_object, attribute, default=0):
            try:
                return getattr(pe_object, attribute)
            except AttributeError:
                return default

       
        features = {
            "DebugSize": get_pe_attribute(pe.OPTIONAL_HEADER, 'DebugSize'),
            "DebugRVA": get_pe_attribute(pe.OPTIONAL_HEADER, 'DebugRVA'),
            "MajorImageVersion": get_pe_attribute(pe.OPTIONAL_HEADER, 'MajorImageVersion'),
            "MajorOSVersion": get_pe_attribute(pe.OPTIONAL_HEADER, 'MajorOSVersion'),
            "ExportRVA": get_pe_attribute(pe.DIRECTORY_ENTRY_EXPORT.struct, 'VirtualAddress', 0) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            "ExportSize": get_pe_attribute(pe.DIRECTORY_ENTRY_EXPORT.struct, 'Size', 0) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            "IatVRA": get_pe_attribute(pe.DIRECTORY_ENTRY_IAT.struct, 'VirtualAddress', 0) if hasattr(pe, 'DIRECTORY_ENTRY_IAT') else 0,
            "MajorLinkerVersion": get_pe_attribute(pe.OPTIONAL_HEADER, 'MajorLinkerVersion'),
            "MinorLinkerVersion": get_pe_attribute(pe.OPTIONAL_HEADER, 'MinorLinkerVersion'),
            "NumberOfSections": len(pe.sections),
            "SizeOfStackReserve": get_pe_attribute(pe.OPTIONAL_HEADER, 'SizeOfStackReserve'),
            "DllCharacteristics": get_pe_attribute(pe.OPTIONAL_HEADER, 'DllCharacteristics'),
            "ResourceSize": sum([section.SizeOfRawData for section in pe.sections]),
            "BitcoinAddresses": 0  # This would depend on your use case, as this feature might need to be extracted elsewhere.
        }

        return features

    except Exception as e:
        print(f"Error processing the file: {e}")
        return None


pe_path = r"C:\ransomwaredetectionapp\data\Rar.exe"  # Ensure this path is correct
features = extract_features(pe_path)
if features:
    print(features)
