from ghidra.program.model.symbol import RefType
import json

def getAddress(address):
    return currentProgram.getAddressFactory().getAddress(address)

inline_table = {}

memory = currentProgram.getMemory()
referenceManager = currentProgram.getReferenceManager()
sancovGuards = memory.getBlock("__sancov_guards")
if sancovGuards is None:
    print("__sancov_guards segment not found")
else:
    startAddress = sancovGuards.getStart()
    endAddress = sancovGuards.getEnd()

    for address in range(startAddress.getOffset(), endAddress.getOffset(), 4):
        references = referenceManager.getReferencesTo(getAddress(hex(address)[2:-1]))

        for ref in references:
                function = getFunctionContaining(ref.getFromAddress())
                if function is not None:
                    try:
                        signature = function.getName()
                        if signature in inline_table:
                            continue
                        else:
                            inline_table[signature] = (address - startAddress.getOffset()) / 4
                        
                    except InvalidInputException as e:
                        print("Error obtaining function signature: " + str(e))

print(inline_table)
with open("D:\out.json", 'w') as json_file:
    json.dump(inline_table, json_file, indent=4)
