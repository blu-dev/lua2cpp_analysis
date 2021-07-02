// Performs more analysis on lua2cpp modules for Super Smash Bros. Ultimate
//@author blujay
//@category 
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.cparser.C.CParser;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.memstate.MemoryBank;
import ghidra.pcode.memstate.MemoryPageBank;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import java.util.zip.CRC32;
import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

class Strings {
	public String first;
	public String second;
	
	public Strings(String f, String s) {
		first = f; second = s;
	}
}

class StructStrings {
	public static final String Hash40MapEntry = 
			"struct Hash40MapEntry {" +
			"	void* next;" +
			"	Hash40 key;" +
			"	Hash40 also_key;" +
			"	void* value;" +
			"};";
	public static final String Hash40Map =
			"struct Hash40Map {" +
			"	Hash40MapEntry** buckets;" +
			"	ulonglong bucketCount;" +
			"};";
	public static final String L2CAgent =
			"struct L2CAgent {" +
			"	void** vtable;" +
			"	lua_State* luaStateAgent;" +
			"	Hash40Map functions;" +
			"	undefined8 field_0x20;" +
			"	undefined8 field_0x28;" +
			"   undefined8 field_0x30;" +
			"   BattleObject* battleObject;" +
			"   BattleObjectModuleAccessor* moduleAccessor;" +
			"};";
	public static final String AgentBaseFiberStruct = 
			"struct AgentBaseFiberStruct {" +
			"   Fiber field_0x0;" +
			"   undefined8 field_0x8;" +
			"   undefined4 field_0x10;" +
			"   undefined4 filed_0x14;" +
			"};";
	public static final String L2CAgentBase =
			"struct L2CAgentBase {" +
			"	void** vtable;" +
			"	lua_State* luaStateAgent;" +
			"	Hash40Map functions;" +
			"	undefined8 field_0x20;" +
			"	undefined8 field_0x28;" +
			"   undefined8 field_0x30;" +
			"   BattleObject* battleObject;" +
			"   BattleObjectModuleAccessor* moduleAccessor;" +
			"   undefined8 field_0x48;" +
			"   undefined8 field_0x50;" +
			"   undefined8 field_0x58;" +
			"   AgentBaseFiberStruct field_0x60[4];" +
			"   undefined2 field_0xc0;" +
			"   undefined field_0xc2[6];" +
			"};";
	public static final String L2CFighterBase =
			"struct L2CFighterBase {" +
			"	void** vtable;" +
			"	lua_State* luaStateAgent;" +
			"	Hash40Map functions;" +
			"	undefined8 field_0x20;" +
			"	undefined8 field_0x28;" +
			"   undefined8 field_0x30;" +
			"   BattleObject* battleObject;" +
			"   BattleObjectModuleAccessor* moduleAccessor;" +
			"   undefined8 field_0x48;" +
			"   undefined8 field_0x50;" +
			"   undefined8 field_0x58;" +
			"   AgentBaseFiberStruct field_0x60[4];" +
			"   undefined2 field_0xc0;" +
			"   undefined field_0xc2[6];" +
			"   L2CValue globalTable;" +
			"   L2CValue field_0xd8;" +
			"   L2CValue field_0xe8;" +
			"   L2CValue field_0xf8;" +
			"   L2CValue field_0x108;" +
			"};";
	public static final String L2CWeaponCommon =
			"struct L2CWeaponCommon {" +
			"	void** vtable;" +
			"	lua_State* luaStateAgent;" +
			"	Hash40Map functions;" +
			"	undefined8 field_0x20;" +
			"	undefined8 field_0x28;" +
			"   undefined8 field_0x30;" +
			"   BattleObject* battleObject;" +
			"   BattleObjectModuleAccessor* moduleAccessor;" +
			"   undefined8 field_0x48;" +
			"   undefined8 field_0x50;" +
			"   undefined8 field_0x58;" +
			"   AgentBaseFiberStruct field_0x60[4];" +
			"   undefined2 field_0xc0;" +
			"   undefined field_0xc2[6];" +
			"   L2CValue globalTable;" +
			"   L2CValue field_0xd8;" +
			"   L2CValue field_0xe8;" +
			"   L2CValue field_0xf8;" +
			"   L2CValue field_0x108;" +
			"};";
	public static final String L2CFighterCommon =
			"struct L2CFighterCommon {" +
			"	void** vtable;" +
			"	lua_State* luaStateAgent;" +
			"	Hash40Map functions;" +
			"	undefined8 field_0x20;" +
			"	undefined8 field_0x28;" +
			"   undefined8 field_0x30;" +
			"   BattleObject* battleObject;" +
			"   BattleObjectModuleAccessor* moduleAccessor;" +
			"   undefined8 field_0x48;" +
			"   undefined8 field_0x50;" +
			"   undefined8 field_0x58;" +
			"   AgentBaseFiberStruct field_0x60[4];" +
			"   undefined2 field_0xc0;" +
			"   undefined field_0xc2[6];" +
			"   L2CValue globalTable;" +
			"   L2CValue field_0xd8;" +
			"   L2CValue field_0xe8;" +
			"   L2CValue field_0xf8;" +
			"   L2CValue field_0x108;" +
			"   L2CValue field_0x118;" +
			"   L2CValue field_0x128;" +
			"   L2CValue field_0x138;" +
			"   L2CValue field_0x148;" +
			"   L2CValue field_0x158;" +
			"   L2CValue field_0x168;" +
			"   L2CValue field_0x178;" +
			"   L2CValue field_0x188;" +
			"   L2CValue field_0x198;" +
			"   L2CValue field_0x1a8;" +
			"   L2CValue field_0x1b8;" +
			"   L2CValue field_0x1c8;" +
			"   L2CValue field_0x1d8;" +
			"   L2CValue field_0x1e8;" +
			"   L2CValue field_0x1f8;" +
			"   L2CValue field_0x208;" +
			"   L2CValue field_0x218;" +
			"};";
	public static final String[] STRUCTS = new String[] {
			Hash40MapEntry, Hash40Map, L2CAgent, AgentBaseFiberStruct,
			L2CAgentBase, L2CFighterBase, L2CWeaponCommon, L2CFighterCommon
	};
	public static final String[] CATEGORIES = new String[] {
			"/lib", "/lib", "/lib", "/lib", "/lua2cpp", "/lua2cpp", "/lua2cpp", "/lua2cpp"
	};
}

class ConditionMap {
	static final Strings[] PAIRS = new Strings[] {
			new Strings("STATUS_PRE", "pre"),
			new Strings("STATUS_MAIN", "main"),
			new Strings("STATUS_END", "end"),
			new Strings("INIT_STATUS", "init"),
			new Strings("EXEC_STATUS", "exec"),
			new Strings("EXEC_STOP", "exec_stop"),
			new Strings("EXEC_STATUS_POST", "exec_post"),
			new Strings("EXIT_STATUS", "exit"),
			new Strings("MAP_CORRECTION", "map_correct"),
			new Strings("FIX_CAMERA", "fix_cam"),
			new Strings("FIX_POS_SLOW", "fix_pos_slow"),
			new Strings("CHECK_DAMAGE", "check_dmg"),
			new Strings("CHECK_ATTACK", "check_atk"),
			new Strings("ON_CHANGE_LR", "on_change_lr"),
			new Strings("NOTIFY_EVENT_GIMMICK", "notify_event_gimmick"),
			new Strings("CALC_PARAM", "calc_param")
	};
	
	public static String getNamespaceName(String conditionName) {
		for (Strings ss : PAIRS) {
			if (ss.first.equals(conditionName))
				return ss.second;
		}
		return null;
	}
}

class InstructionMasks {
	public static final int RET_MASK = 0b1111_1111_1111_1111_1111_1100_0001_1111;
	public static final int RET_REQUIRED = 0b1101_0110_0101_1111_0000_0000_0000_0000;
	
	public static final int MOVZ64_MASK = 0b1111_1111_1000_0000_0000_0000_0000_0000;
	public static final int MOVZ64_REQUIRED = 0b1101_0010_1000_0000_0000_0000_0000_0000;
	
	public static final int MOVK64_MASK = 0b1111_1111_1000_0000_0000_0000_0000_0000;
	public static final int MOVK64_REQUIRED = 0b1111_0010_1000_0000_0000_0000_0000_0000;
	
	public static final int CMP_MASK = 0b1111_1111_0010_0000_0000_0000_0001_1111;
	public static final int CMP_REQUIRED = 0b1110_1011_0000_0000_0000_0000_0001_1111;
	
	public boolean isRet(int instr) {
		return (instr & RET_MASK) == RET_REQUIRED;
	}
	
	public boolean isMovZ64(int instr) {
		return (instr & MOVZ64_MASK) == MOVZ64_REQUIRED;
	}
	
	public boolean isMovK64(int instr) {
		return (instr & MOVK64_MASK) == MOVK64_REQUIRED;
	}
	
	public boolean isCmp(int instr) {
		return (instr & CMP_MASK) == CMP_REQUIRED;
	}
}

class HashEmulator {
	Address currentAddress;
	ArrayList<Long> hashes;
	ArrayList<Address> vtables;
	long[] registers;
	
	public HashEmulator(Address starting) {
		currentAddress = starting;
		hashes = new ArrayList<>();
		registers = new long[31];
	}
	
	public ArrayList<Long> getHashes() {
		
		return null;
	}
}

public class Lua2CPPAnalysis extends GhidraScript {
	
	private Address derefAddress(Address addr) throws Exception {
		byte[] bytes = getBytes(addr, 8);
		String formatString = String.format("%02x%02x%02x%02x%02x%02x%02x%02x", bytes[7], bytes[6], bytes[5], bytes[4], bytes[3], bytes[2], bytes[1], bytes[0]);
		if (!formatString.startsWith("00000071"))
			return null;
		return getAddressFactory().getAddress(formatString);
	}
	
	private static long hash40(String str) {
		CRC32 crc = new CRC32();
		crc.update(str.getBytes());
		long length = (long)str.length() << 32;
		long value = crc.getValue();
		return length | value;
	}
	
	private void fixExistingTypes() throws Exception {
		SymbolTable symTable = getCurrentProgram().getSymbolTable();
		DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
		Namespace l2cagent = symTable.getNamespace("L2CAgent", symTable.getNamespace("lib", null));
		if (!(l2cagent instanceof GhidraClass)) {
			StructureDataType agentType = new StructureDataType(new CategoryPath("/lib"), "L2CAgent", 0x48);
			dtm.addDataType(agentType, DataTypeConflictHandler.REPLACE_HANDLER);
			NamespaceUtils.convertNamespaceToClass(l2cagent);
		}
		StructureDataType fiber = new StructureDataType(new CategoryPath("/Demangler/phx"), "Fiber", 8);
		dtm.addDataType(fiber,  DataTypeConflictHandler.REPLACE_HANDLER);
		StructureDataType l2cvalue = new StructureDataType(new CategoryPath("/lib"), "L2CValue", 16);
		dtm.addDataType(l2cvalue,  DataTypeConflictHandler.REPLACE_HANDLER);
		TypedefDataType newHash40 = new TypedefDataType(new CategoryPath("/Demangler/phx"), "Hash40", new UnsignedLongDataType());
		dtm.addDataType(newHash40,  DataTypeConflictHandler.REPLACE_HANDLER);
    	CParser parser = new CParser(dtm);
    	for (int i = 0; i < StructStrings.STRUCTS.length; i++) { 
    		DataType dt = parser.parse(StructStrings.STRUCTS[i]);
    		dt.setCategoryPath(new CategoryPath(StructStrings.CATEGORIES[i]));
    		dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
    	}
//		TypedefDataType weaponCommon = new TypedefDataType(new CategoryPath("/lua2cpp"), "L2CWeaponCommon", dtm.getDataType("/lua2cpp/L2CFighterBase"));
//		dtm.addDataType(weaponCommon, DataTypeConflictHandler.REPLACE_HANDLER);
	}
	
	private void makeThiscalls() throws Exception {
		fixExistingTypes();
		Program program = getCurrentProgram();
		SymbolTable symTable = program.getSymbolTable();
		Namespace libNamespace = symTable.getNamespace("lib", null);
		Namespace lua2cppNamespace = symTable.getNamespace("lua2cpp", null);
		SymbolIterator syms = symTable.getAllSymbols(false);
		for (Symbol s : syms) {
			String name = s.getName();
			if (name.startsWith("_ZN3lib8L2C") || name.startsWith("_ZN7lua2cpp") ||
					name.startsWith("_ZNK3lib8L2C") || name.startsWith("_ZNK7lua2cpp")) {
				Function f = getFunctionAt(s.getAddress());
				if (f == null)
					continue;
				f.setCallingConvention("__thiscall");
				for (Parameter p : f.getParameters()) {
					DataType dt = p.getDataType();
					if (dt.getPathName().equals("/lib/L2CValue"))
						p.setDataType(new Pointer64DataType(dt), SourceType.USER_DEFINED);
				}
			}
		}
	}
	
	private Function changeOrMakeFunction(String newName, Address where, Namespace parent) throws Exception {
		Function f = getFunctionAt(where);
		if (f == null) {
			disassemble(where);
			f = createFunction(where, null);
		}
		f.setName(newName, SourceType.USER_DEFINED);
		f.setCallingConvention("__thiscall");
		if (parent != null)
			f.setParentNamespace(parent);
		return f;
	}
	
	private Address findStartOfSetters(Address start, boolean isFighter) {
		// WARNING: THIS IS EXTREMELY HACKY
		// THIS CODE IS SUS
		
		SymbolTable st = getCurrentProgram().getSymbolTable();
		
		for (Instruction instr = getInstructionAt(start); ; start = start.add(4), instr = getInstructionAt(start)) {
			String txt = instr.toString();
			if (txt.startsWith("bl")){
				Address addr = parseAddress(txt.split(" ")[1]);
				if (isFighter) {
					if (getSymbolAt(addr).getName().startsWith("sub_")) {
						return start.add(4);
					}
				} else {
					if (getSymbolAt(addr).getName().startsWith("reserve_")) {
						return start.add(4);
					}
				}
			}
		}
	}
	
	private String formatStatusFuncName(String statusKind) {
		String statusKindName = statusKind.split("STATUS_KIND_")[1];
		String[] words = statusKindName.split("_");
		String ret = "";
		for (String word : words) {
			if (!words.equals("")) {
				ret += word.substring(0, 1).toUpperCase() + word.substring(1).toLowerCase();
			}
		}
		return ret;
	}
	
	private Namespace getOrCreateNamespace(Namespace parent, String namespace) throws Exception {
		SymbolTable st = getCurrentProgram().getSymbolTable();
		Namespace ret = st.getNamespace(namespace, parent);
		if (ret == null)
			ret = st.createNameSpace(parent, namespace, SourceType.USER_DEFINED);
		return ret;
	}
	
	private Namespace getNamespaceFromCondition(Namespace parent, String condition) throws Exception {
		String conditionName = condition.split("STATUS_FUNC_")[1];
		return getOrCreateNamespace(parent, ConditionMap.getNamespaceName(conditionName));
	}
	
	private Address getAdrpAdd(Address start) throws Exception {
		Instruction adrp = getInstructionAt(start);
		Instruction add = getInstructionAt(start.add(4));
		Address ret = parseAddress(adrp.toString().split("0x")[1]);
		ret = ret.add(Long.parseLong(add.toString().split("0x")[1], 16));
		return ret;
	}
	
	private Function getFunctionFromBl(Instruction instr) throws Exception {
		return getFunctionAt(parseAddress(instr.toString().split("0x")[1]));
	}
	
	private boolean doesReturnOnStack(Function func) throws Exception {
		Address end = func.getBody().getMaxAddress();
		for (Address addr = func.getBody().getMinAddress(); addr.compareTo(end) < 0; addr = addr.add(4)) {
			Instruction instr = getInstructionAt(addr);
			for (Object o : instr.getResultObjects()) {
				if (func.getName().equals("Appeal"))
					println(o.toString());
				if (o.toString().equals("x8"))
					return false;
			}
			for (Object o : instr.getInputObjects()) {
				if (o.toString().equals("x8"))
					return true;
			}
		}
		return false;
	}
	
	private void fixInternalSymbolCalls(Function func) throws Exception {
		DataType valueType = getCurrentProgram().getDataTypeManager().getDataType("/lib/L2CValue");
		Address end = func.getBody().getMaxAddress();
		for (Address addr = func.getBody().getMinAddress(); addr.compareTo(end) < 0; addr = addr.add(4)) {
			Instruction instr = getInstructionAt(addr);
			if (instr != null && instr.toString().startsWith("bl ")) {
				Function sub = getFunctionFromBl(instr);
				if (sub == null)
					continue;
				for (instr = instr.getPrevious(); instr.toString().startsWith("mov") || instr.toString().startsWith("add"); instr = instr.getPrevious()) {
					for (Object o : instr.getResultObjects()) {
						if (o.toString().equals("x8")) {
							println(sub.getName());
							ParameterImpl returnParam = new ParameterImpl("return_value", new Pointer64DataType(valueType), currentProgram.getRegister("x8"), currentProgram);
							sub.setCustomVariableStorage(true);
							sub.addParameter(returnParam, SourceType.USER_DEFINED);
							sub.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
						}
					}
				}
			}
		}
	}
	
	private String snakeCaseToPascalCase(String str) {
		String[] words = str.split("_");
		String ret = "";
		for (String word : words) {
			ret += word.substring(0, 1).toUpperCase() + word.substring(1).toLowerCase();
		}
		return ret;
	}
	
	private void makeStatuses(String agentName, Address vtableAddress, boolean isAgentFighter, boolean shouldNamespace) throws Exception {
		Program program = getCurrentProgram();
		String properAgentName = snakeCaseToPascalCase(agentName);
		String fileName = getProgramFile().getName();
		
		// Making the typedef
		String typeCatPath = "/" + fileName;
		DataTypeManager dtm = program.getDataTypeManager();
		if (dtm.getCategory(new CategoryPath(typeCatPath)) == null)
			dtm.createCategory(new CategoryPath(typeCatPath));
		TypedefDataType agentType = null;
		if (isAgentFighter) 
			agentType = new TypedefDataType(new CategoryPath(typeCatPath), "L2CFighter" + properAgentName, dtm.getDataType("/lua2cpp/L2CFighterCommon"));
		else
			agentType = new TypedefDataType(new CategoryPath(typeCatPath), "L2CWeapon" + properAgentName, dtm.getDataType("/lua2cpp/L2CWeaponCommon"));
		dtm.addDataType(agentType, DataTypeConflictHandler.REPLACE_HANDLER);
		
		// Make the namespace class
		SymbolTable symTable = program.getSymbolTable();
		{
			Symbol existing = symTable.getClassSymbol(agentType.getName(), null);
			if (existing != null)
				existing.delete();
		}
		GhidraClass agentClass = symTable.createClass(null, agentType.getName(), SourceType.USER_DEFINED);
		
		// Fill out the rest of the vtable
		Address destructor = derefAddress(vtableAddress);
		Address deleter = derefAddress(vtableAddress.add(8));
		Address setter = derefAddress(vtableAddress.add(8 * 9));
		
		changeOrMakeFunction("~" + agentType.getName(), destructor, agentClass);
		changeOrMakeFunction("~~" + agentType.getName(), deleter, agentClass);
		changeOrMakeFunction("SetStatusScripts", setter, agentClass);
		
		// Autocreate status functions
		Namespace agentStatuses = getOrCreateNamespace(agentClass, "status");
		Address setterStart = findStartOfSetters(setter, isAgentFighter);
		ArrayList<Integer> stores = new ArrayList<>();
		ArrayList<Address> returnStack = new ArrayList<>();
		@SuppressWarnings("deprecation")
		Symbol constValueTable = symTable.getSymbol("const_value_table__", symTable.getNamespace("L2CAgentGeneratedBase", symTable.getNamespace("lua2cpp", null))); // continue tomrrow
		for (Instruction instr = getInstructionAt(setterStart); ; setterStart = setterStart.add(4), instr = getInstructionAt(setterStart)) {
			String instrString = instr.toString();
			if (instrString.startsWith("ret")) {
				if (returnStack.size() != 0) {
					setterStart = returnStack.get(returnStack.size() - 1);
					returnStack.remove(returnStack.size() - 1);
					stores.clear();
				} else {
					break;
				}
			} else if (instrString.startsWith("ldr w1")) {
				String inputs = instrString.split("ldr w1,")[1];
				String[] inputList = inputs.split(",");
				int offset = 0;
				if (inputList.length != 2) {
					Instruction movInstr = getInstructionAt(setterStart.subtract(4));
					String movString = movInstr.toString();
					for (Object o : movInstr.getInputObjects()) {
						String s = o.toString();
						if (s.startsWith("0x")) {
							offset += Integer.parseInt(s.split("0x")[1], 16);
							stores.add(offset);
						}
					}
				} else {					
					for (Object o : instr.getInputObjects()) {
						String s = o.toString();
						if (s.startsWith("0x")) {
							offset += Integer.parseInt(s.split("0x")[1], 16);
							stores.add(offset);
						}
					}
				}
			} else if (instrString.startsWith("bl")) {
				Address gotoAddress = parseAddress(instrString.split(" ")[1]);
				Symbol potential = getSymbolAt(gotoAddress);
				if (potential != null && potential.getName().equals("sv_set_status_func")) {
					Address adrpAddress = setterStart.subtract(20);
					Address adrpLoaded = parseAddress(getInstructionAt(adrpAddress).toString().split("0x")[1]);
					for (Object o : getInstructionAt(adrpAddress.add(4)).getInputObjects()) {
						String s = o.toString();
						if (s.startsWith("0x")) {
							println(adrpAddress.toString());
							adrpLoaded = adrpLoaded.add(Long.parseLong(s.split("0x")[1], 16));
							break;
						}
					}
					String statusKind = getSymbolAt(constValueTable.getAddress().add(stores.get(0))).getName();
					while (!statusKind.contains("_STATUS_KIND_")) {
						stores = new ArrayList<Integer>(stores.subList(1, stores.size()));
						statusKind = getSymbolAt(constValueTable.getAddress().add(stores.get(0))).getName();
					}
					String condition = getSymbolAt(constValueTable.getAddress().add(stores.get(1))).getName();
					Function f = null;
					if (shouldNamespace) {
						Namespace conditionNs = getNamespaceFromCondition(agentStatuses, condition);
						f = changeOrMakeFunction(formatStatusFuncName(statusKind), adrpLoaded, conditionNs);
					} else {
						f = changeOrMakeFunction(formatStatusFuncName(statusKind) + "_" + ConditionMap.getNamespaceName(condition.split("STATUS_FUNC_")[1]), adrpLoaded, agentStatuses);
					}
					disassemble(f.getBody().getMinAddress());
					stores.clear();
				} else if (potential != null && potential.getName().startsWith("FUN")) {
					stores.clear();
					returnStack.add(setterStart);
					setterStart = gotoAddress;
				}
			}
		}
		
		// Autocreate main status loop functions
//		Symbol subShiftStatusMain = symTable.getSymbol("sub_shift_status_main", symTable.getNamespace("L2CFighterCommon", symTable.getNamespace("lua2cpp", null)));
		SymbolIterator children = shouldNamespace ? symTable.getChildren(symTable.getNamespaceSymbol("main", agentStatuses)) : symTable.getChildren(agentStatuses.getSymbol());
		for (Symbol child : children) {
			Function parent = getFunctionAt(child.getAddress());
			if (parent == null)
				continue;
			if (!shouldNamespace && !parent.getName().endsWith("_main"))
				continue;
			for (Address addr = parent.getBody().getMinAddress(); addr.compareTo(parent.getBody().getMaxAddress()) < 0; addr = addr.add(4)) {
				Instruction instr = getInstructionAt(addr);
				if (instr != null && instr.toString().startsWith("bl")) {
					Function blFunc = getFunctionFromBl(instr);
					if (blFunc == null || !(blFunc.getName().equals("sub_shift_status_main") || blFunc.getName().equals("fastshift")))
						continue;
					Address fromAddress = addr;
					for (; !getInstructionAt(fromAddress).toString().startsWith("adrp"); fromAddress = fromAddress.subtract(4));
					fromAddress = getAdrpAdd(fromAddress);
					disassemble(fromAddress);
					if (shouldNamespace) {						
						Namespace parentFunc = getOrCreateNamespace(symTable.getNamespace("main", agentStatuses), parent.getName());
						changeOrMakeFunction("loop", fromAddress, parentFunc);
					} else {
						changeOrMakeFunction(parent.getName() + "_loop", fromAddress, agentStatuses);
					}
					break;
				}
			}
		}
		
		// Fix the return types
		DataType valueType = getCurrentProgram().getDataTypeManager().getDataType("/lib/L2CValue");
		for (Symbol child : symTable.getChildren(symTable.getNamespaceSymbol("status", symTable.getNamespace(agentClass.getName(), null)))) {
			if (!shouldNamespace) {
				Function f = getFunctionAt(child.getAddress());
				if (f != null) {
					f.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
					ParameterImpl returnParam = new ParameterImpl("return_value", new Pointer64DataType(valueType), currentProgram.getRegister("x8"), currentProgram);
					f.setCustomVariableStorage(true);
					f.getParameter(0).setDataType(new Pointer64DataType(agentType), SourceType.USER_DEFINED);
					f.addParameter(returnParam, SourceType.USER_DEFINED);
					fixInternalSymbolCalls(f);
				}
				continue;
			}
			for (Symbol s : symTable.getChildren(child)) {
				Function f = getFunctionAt(s.getAddress());
				if (f != null) {
					f.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
					ParameterImpl returnParam = new ParameterImpl("return_value", new Pointer64DataType(valueType), currentProgram.getRegister("x8"), currentProgram);
					f.setCustomVariableStorage(true);
					f.getParameter(0).setDataType(new Pointer64DataType(agentType), SourceType.USER_DEFINED);
					f.addParameter(returnParam, SourceType.USER_DEFINED);
					fixInternalSymbolCalls(f);
				} else {
					for (Symbol ss : symTable.getChildren(s)) {
						Function ff = getFunctionAt(ss.getAddress());
						if (ff != null) {
							ff.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
							ParameterImpl returnParam = new ParameterImpl("return_value", new Pointer64DataType(valueType), currentProgram.getRegister("x8"), currentProgram);
							ff.setCustomVariableStorage(true);
							ff.getParameter(0).setDataType(new Pointer64DataType(agentType), SourceType.USER_DEFINED);
							ff.addParameter(returnParam, SourceType.USER_DEFINED);
							fixInternalSymbolCalls(ff);
						}
					}
				}
			}
		}
		
		Symbol vtable = createLabel(vtableAddress, "vtable", true);
		vtable.setNamespace(agentClass);
	}
	
	public void checkLuaconsts() throws Exception {
		SymbolTable symTable = getCurrentProgram().getSymbolTable();
		Symbol constValueTable = symTable.getSymbol("const_value_table__", symTable.getNamespace("L2CAgentGeneratedBase", symTable.getNamespace("lua2cpp", null)));
		Address cvtAddress = constValueTable.getAddress();
		if (getSymbolAt(cvtAddress, "LUA_SCRIPT_LINE_MAX") == null) {
			String filePath = askString("LuaDictionary Filepath", "Please enter the LuaDictionary filepath:");
			BufferedReader reader = new BufferedReader(new FileReader(filePath));
			for (String line = reader.readLine(); line != null; line = reader.readLine()) {
				String[] parts = line.split(":", 2);
				long offset = Long.decode("0x" + parts[0]);
				createLabel(cvtAddress.add(offset), parts[1], true, SourceType.USER_DEFINED);
			}
		}
	}
	
    public void run() throws Exception {
//TODO Add User Code Here
    	checkLuaconsts();
    	makeThiscalls();
    	while (askYesNo("Autocreate Status Functions", "Are there more status agents to autocreate?")) {
    		String name = askString("Agent Name", "Enter the agent name:");
    		Address addr = askAddress("Agent VTable", "Enter the address for the vtable:");
    		boolean isFighter = true;
    		boolean shouldNamespace = false;
    		try {
    			String choice = askChoice("Agent type", "What is the type of agent?", Arrays.asList(new String[] {
    					"Fighter", "Weapon"
    			}), "Fighter");
    			isFighter = choice.equals("Fighter");
    			choice = askChoice("Generation type", "How would you like the status functions generated?", Arrays.asList(new String[] {
        				"With namespaces (e.g. L2CFighterMario::status::main::AttackS4)",
        				"Without namespaces (e.g. L2CFighterMario::status::AttackS4_main)"
        			}), "With namespaces (e.g. L2CFighterMario::status::main::AttackS4)");
        			shouldNamespace = choice.equals("With namespaces (e.g. L2CFighterMario::status::main::AttackS4)");
    		}catch (CancelledException ce) {
    			continue;
    		}
    		makeStatuses(name, addr, isFighter, shouldNamespace);
    	}
//    	makeThiscalls();
//    	println(findStartOfSetters(parseAddress("71000080a0")).toString());
    }

}
