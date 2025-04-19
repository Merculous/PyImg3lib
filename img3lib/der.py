
import asn1
from Crypto.PublicKey import RSA

# TODO
# A lot of this code was helped with ChatGPT.
# I need to continue working on this code so
# that I actually have more knowledge on how
# to work with DER data.

# TODO
# Start using Enum

class DERTypes:
    Primitive = asn1.Types.Primitive
    Constructed = asn1.Types.Constructed


def class_id_to_string(cls):
    return {
        asn1.Classes.Universal: "Universal",
        asn1.Classes.Application: "Application",
        asn1.Classes.Context: "Context",
        asn1.Classes.Private: "Private",
    }.get(cls, "Unknown")


def tag_id_to_string(tag):
    return {
        asn1.Numbers.Boolean: "BOOLEAN",
        asn1.Numbers.Integer: "INTEGER",
        asn1.Numbers.BitString: "BIT STRING",
        asn1.Numbers.OctetString: "OCTET STRING",
        asn1.Numbers.Null: "NULL",
        asn1.Numbers.ObjectIdentifier: "OBJECT IDENTIFIER",
        asn1.Numbers.Enumerated: "ENUMERATED",
        asn1.Numbers.Sequence: "SEQUENCE",
        asn1.Numbers.Set: "SET",
        asn1.Numbers.PrintableString: "PRINTABLE STRING",
        asn1.Numbers.IA5String: "IA5 STRING",
        asn1.Numbers.GeneralizedTime: "GENERALIZED TIME",
    }.get(tag, "Unknown")


def value_to_string(tag, value):
    if tag == asn1.Numbers.ObjectIdentifier:
        return '.'.join(str(x) for x in value)
    elif isinstance(value, bytes):
        return value.hex()
    return str(value)


def decodeDER(der_data):
    decoder = asn1.Decoder()
    decoder.start(der_data)

    def parseTags(stream):
        data = []

        while not stream.eof():
            tag = stream.peek()

            if tag.typ == DERTypes.Primitive:
                tag, value = stream.read()
                data.append({
                    'class': class_id_to_string(tag.cls),
                    'tag': tag_id_to_string(tag.nr),
                    'value': value_to_string(tag.nr, value)
                })

            elif tag.typ == DERTypes.Constructed:
                stream.enter()
                value = parseTags(stream)
                stream.leave()
                data.append({
                    'class': class_id_to_string(tag.cls),
                    'tag': tag_id_to_string(tag.nr),
                    'value': value
                })

        return data

    tags = parseTags(decoder)
    return tags


def printDER(data, indent=0):
    spacing = ' ' * indent

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):

                print(f"{spacing}{item['class']} {item['tag']}:")

                if isinstance(item['value'], list):
                    printDER(item['value'], indent + 2)

                else:
                    print(f"{spacing}  {item['value']}")

            else:
                print(f"{spacing}{item}")

    elif isinstance(data, dict):
        for key, value in data.items():
            print(f"{spacing}{key}:")
            printDER(value, indent + 2)

    else:
        print(f"{spacing}{data}")


def searchDER(parsed_values, search_class, search_tag):
    results = []

    def searchRecursively(data):
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if item['class'] == class_id_to_string(search_class) and item['tag'] == tag_id_to_string(search_tag):
                        results.append(item)

                    if isinstance(item['value'], list):
                        searchRecursively(item['value'])

                else:
                    searchRecursively(item)

        elif isinstance(data, dict):
            for value in data.values():
                searchRecursively(value)

    searchRecursively(parsed_values)
    return results


def extractPublicKeyFromDER(data):
    decoded = decodeDER(data)
    keys = []

    for x in searchDER(decoded, asn1.Classes.Universal, asn1.Numbers.BitString):
        key = b''.fromhex(x['value'])

        try:
            pKey = RSA.import_key(key)
        except ValueError:
            continue

        keys.append(pKey)

    key = keys[-1]
    return key


def extractNestedImages(data):
    strings = []

    for x in searchDER(data, asn1.Classes.Universal, asn1.Numbers.OctetString):
        strings.append(x['value'])

    return b''.fromhex(strings[-1])[2:]


def extractSHA1HashesFromAPTicket(data):
    hashes = []

    for x in searchDER(data, asn1.Classes.Context, None):
        if not isinstance(x['value'], str):
            continue

        sha1Hash = x['value']

        if len(sha1Hash) != 40:
            continue

        hashes.append(sha1Hash)

    return hashes
