//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import java.util.ArrayList;
import ghidra.program.database.symbol.NamespaceManager;

class Pair {
	public String name;
	public int value;
	public Pair(String n, int v) {
		name = n;
		value = v;
	}
}

class StringPair {
	public String first;
	public String second;
	public StringPair(String f, String s) {
		first = f;
		second = s;
	}
}
public class ModuleFiller extends GhidraScript {
	
	
	
	static final int BR_BITMASK = 0b1111_1111_1111_1111_1111_1100_0001_1111;
	static final int BR_REQUIRED = 0b1101_0110_0001_1111_0000_0000_0000_0000;
	static final int LDR_BITMASK = 0b1111_1111_1100_0000_0000_0000_0000_0000;
	static final int LDR_REQUIRED = 0b1111_1001_0100_0000_0000_0000_0000_0000;
	static final int LDR_OFFSET = 0b0000_0000_0011_1111_1111_1100_0000_0000;
	
	static final Pair[] PAIRS = new Pair[] {
			new Pair("AbsorberModule", 0x110),
			new Pair("AreaModule", 0xC0),
	        new Pair("ArticleModule", 0x98),
	        new Pair("AttackModule", 0xA0),
	        new Pair("CameraModule", 0x60),
	        new Pair("CancelModule", 0x128),
	        new Pair("CaptureModule", 0x138),
	        new Pair("CatchModule", 0x120),
	        new Pair("ColorBlendModule", 0x70),
	        new Pair("ComboModule", 0xB8),
	        new Pair("ControlModule", 0x48),
	        new Pair("DamageModule", 0xA8),
	        new Pair("EffectModule", 0x140),
	        new Pair("GrabModule", 0x158),
	        new Pair("GroundModule", 0x58),
	        new Pair("HitModule", 0xB0),
	        new Pair("InkPaintModule", 0x198),
	        new Pair("ItemModule", 0xC8),
	        new Pair("JostleModule", 0x118),
	        new Pair("KineticModule", 0x68),
	        new Pair("LinkModule", 0xD0),
	        new Pair("LuaModule", 0x190),
	        new Pair("ModelModule", 0x78),
	        new Pair("MotionAnimcmdModule", 0x188),
	        new Pair("MotionModule", 0x88),
	        new Pair("PhysicsModule", 0x80),
	        new Pair("PostureModule", 0x38),
	        new Pair("ReflectModule", 0xF8),
	        new Pair("ReflectorModule", 0x108),
	        new Pair("SearchModule", 0xE0),
	        new Pair("ShadowModule", 0x180),
	        new Pair("ShakeModule", 0x168),
	        new Pair("ShieldModule", 0x100),
	        new Pair("SlopeModule", 0x160),
	        new Pair("SlowModule", 0x170),
	        new Pair("SoundModule", 0x148),
	        new Pair("StatusModule", 0x40),
	        new Pair("StopModule", 0x90),
	        new Pair("TeamModule", 0xD8),
	        new Pair("TurnModule", 0xF0),
	        new Pair("VisibilityModule", 0x150),
	        new Pair("WorkModule", 0x50)
	};
	
	static final StringPair[] MODULE_VTABLES = new StringPair[] {
		    new StringPair("AbsorberModule", "7104e32ff8"),
		    new StringPair("AreaModule", "7104e451d8"),
		    new StringPair("ArticleModule", "7104e2a0a0"),
		    new StringPair("AttackModule", "7104e2a428"),
		    new StringPair("CameraModule", "7104e2ada8"),
		    new StringPair("CancelModule", "7104e45488"),
		    new StringPair("CaptureModule", "7104e2b2c0"),
		    new StringPair("CatchModule", "7104e2b540"),
		    new StringPair("ColorBlendModule", "7104e455b8"),
		    new StringPair("ComboModule", "7104e45780"),
		    new StringPair("ControlModule", "7104e45908"),
		    new StringPair("DamageModule", "7104e460a8"),
		    new StringPair("EffectModule", "7104e466d8"),
		    new StringPair("GrabModule", "7104e2d570"),
		    new StringPair("GroundModule", "7104e46bc0"),
		    new StringPair("HitModule", "7104e47410"),
		    new StringPair("InkPaintModule", "7104e47680"),
		    new StringPair("ItemModule", "7104e47770"),
		    new StringPair("JostleModule", "7104e47a40"),
		    new StringPair("KineticModule", "7104e47bb8"),
		    new StringPair("LinkModule", "7104e2f518"),
		    new StringPair("LuaModule", "7104e481d8"),
		    new StringPair("ModelModule", "7104e48350"),
		    new StringPair("MotionAnimcmdModule", "7104e48ec8"),
		    new StringPair("MotionModule", "7104e487e0"),
		    new StringPair("PhysicsModule", "7104e315b0"),
		    new StringPair("PostureModule", "7104e32020"),
		    new StringPair("ReflectModule", "7104e32378"),
		    new StringPair("ReflectorModule", "7104e32dc8"),
		    new StringPair("SearchModule", "7104e324b0"),
		    new StringPair("ShadowModule", "7104e326c0"),
		    new StringPair("ShakeModule", "7104e48fc0"),
		    new StringPair("ShieldModule", "7104e32898"),
		    new StringPair("SlopeModule", "7104e33228"),
		    new StringPair("SlowModule", "7104e33428"),
		    new StringPair("SoundModule", "7104e490a0"),
		    new StringPair("StatusModule", "7104e494b8"),
		    new StringPair("StopModule", "7104e49710"),
		    new StringPair("TeamModule", "7104e33f78"),
		    new StringPair("TurnModule", "7104e340e8"),
		    new StringPair("VisibilityModule", "7104e341f0"),
		    new StringPair("WorkModule", "7104e49ab0")
		};
	
	public String snakeCaseToPascalCase(String functionName) {
		String[] words = functionName.split("__")[1].split("_impl")[0].split("_");
		String result = "";
		for (String word : words) {
			result += word.substring(0, 1).toUpperCase() + word.substring(1);
		}
		return result;
	}
	
	public int getInstruction(Address addr) throws MemoryAccessException {
		byte[] bytes = getBytes(addr, 4);
		int ret = (bytes[0] & 0xFF) | (bytes[1] & 0xFF) << 8 | (bytes[2] & 0xFF) << 16 | (bytes[3] & 0xFF) << 24;
		return ret;
	}
	
	public int getLdrOffset(int instr) {
		return (instr & LDR_OFFSET) >> 10;
	}
	
	public long getVirtFuncOffset(Address addr) throws Exception {
		int instr = getInstruction(addr), prevInstr = 0;
		while ((instr & BR_BITMASK) != BR_REQUIRED) {
			addr = addr.add(4);
			if ((instr & LDR_BITMASK) == LDR_REQUIRED)
				prevInstr = instr;
			instr = getInstruction(addr);
		}
		if ((prevInstr & LDR_BITMASK) != LDR_REQUIRED) {
			printf("%x", prevInstr);
			throw new Exception();
		}
		return getLdrOffset(prevInstr) << 3;
	}
	
	public Address derefAddress(Address addr) throws Exception {
		byte[] bytes = getBytes(addr, 8);
		String formatString = String.format("%02x%02x%02x%02x%02x%02x%02x%02x", bytes[7], bytes[6], bytes[5], bytes[4], bytes[3], bytes[2], bytes[1], bytes[0]);
		if (!formatString.startsWith("00000071"))
			return null;
		return getAddressFactory().getAddress(formatString);
	}
	
	public GhidraClass getNewClass(String moduleName) throws Exception {
		SymbolTable sm = getCurrentProgram().getSymbolTable();
		if (sm.getClassSymbol(moduleName, null) != null)
			throw new Exception("Cannot edit existing class namespace!");
		return sm.createClass(null, moduleName, SourceType.USER_DEFINED);
	}
	
	public StructureDataType getNewStruct(String moduleName, int size) throws Exception {
		DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
		if (dtm.getCategory(new CategoryPath("/SmashModules")) == null)
			dtm.createCategory(new CategoryPath("/SmashModules"));
		if (dtm.getCategory(new CategoryPath("/SmashModules/" + moduleName)) == null)
			dtm.createCategory(new CategoryPath("/SmashModules/" + moduleName));
		if (dtm.getDataType("/SmashModules/" + moduleName) != null) {
			throw new Exception("Cannot edit existing structure!");
		}
		StructureDataType ret = new StructureDataType(new CategoryPath("/SmashModules"), moduleName, size);
		ret.replaceAtOffset(0, new Pointer64DataType(new Pointer64DataType(DataType.VOID)), -1, "vtbl", null);
		ret.replaceAtOffset(8, new Pointer64DataType(dtm.getDataType("/Demangler/app/BattleObjectModuleAccessor")), -1, "owner", null);
		dtm.addDataType(ret, DataTypeConflictHandler.DEFAULT_HANDLER);
		return ret;
	}
	
	public DataType generateVtableStruct(String moduleName, Address vtableStart, Namespace parent) throws Exception {
		// go through and fix all of them
		Address current = vtableStart;
		for (Address deref = derefAddress(current); deref != null; current = current.add(8), deref = derefAddress(current)) {
			Function f = getFunctionAt(deref);
			if (f == null) {
				println(deref.toString());
				f = createFunction(deref, null);
				if (parent != null)
					f.setParentNamespace(parent);
				f.setCallingConvention("__thiscall");
			}
		}
		
		DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
		
		CategoryPath catPath = new CategoryPath("/SmashModules/" + moduleName);
		StructureDataType ret = new StructureDataType(catPath, "vtable", 0);
		current = vtableStart;
		for (Address deref = derefAddress(current); deref != null; current = current.add(8), deref = derefAddress(current)) {
			Function f = getFunctionAt(deref);
			if (f == null) {
				throw new Exception("Unexpected null function!");
			}
			FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(f, false);
			funcDef.setCategoryPath(catPath);
			if (funcDef.getName().startsWith("~~"))
				funcDef.setName("~~" + moduleName);
			else if (funcDef.getName().startsWith("~"))
				funcDef.setName("~" + moduleName);
			dtm.addDataType(funcDef, DataTypeConflictHandler.DEFAULT_HANDLER);
			ret.add(new Pointer64DataType(funcDef), 8, funcDef.getName(), null);
		}
		dtm.addDataType(ret, DataTypeConflictHandler.DEFAULT_HANDLER);
		return ret;
	}

    public void run() throws Exception {
    	boolean updateInstead = askYesNo("Update", "Do you want to update the BattleObjectModuleAccessor?");
    	if (updateInstead) {
    		DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
//    		DataType moduleAccessor = dtm.getDataType("/Demangler/app/BattleObjectModuleAccessor");
//    		if (moduleAccessor instanceof StructureDataType) {
    			StructureDataType boma = new StructureDataType(
    					new CategoryPath("/Demangler/app"),
    					"BattleObjectModuleAccessor",
    					0x2000
    			);
    					
//    			StructureDataType boma = (StructureDataType)moduleAccessor;
    			for (Pair p : PAIRS) {
    				DataType module = dtm.getDataType("/SmashModules/" + p.name);
    				if (module == null)
    					throw new Exception(p.name);
    				boma.replaceAtOffset(p.value, new Pointer64DataType(module), 8, p.name, null);
    			}
//    			dtm.replaceDataType(boma, boma, false);
    			dtm.addDataType(boma, DataTypeConflictHandler.REPLACE_HANDLER);
//    		}
    		return;
    	}
//    	for (StringPair sp : MODULE_VTABLES) {
//    		Address vtableAddress = getAddressFactory().getAddress(sp.second);
//    		String moduleName = sp.first;
//    		int structSize = 0x1000;
//    		boolean changeNonSymbolNamespace = false;
//    		Program program = getCurrentProgram();
//    		GhidraClass classNamespace = getNewClass(moduleName);
//    		StructureDataType moduleStruct = getNewStruct(moduleName, structSize);
//    		SymbolTable st = program.getSymbolTable();
//    		SymbolIterator si = st.getDefinedSymbols();
//    		Symbol vtableLabel = createLabel(vtableAddress, "vtbl", true, SourceType.USER_DEFINED);
//    		vtableLabel.setNamespace(classNamespace);
//    		Address destructor = derefAddress(vtableAddress);
//    		Address deleter = derefAddress(vtableAddress.add(8));
//    		Function d = getFunctionAt(destructor);
//    		if (d == null) {
//    			d = createFunction(destructor, null);
//    		}
//    		if (!(d.getParentNamespace() instanceof GhidraClass)) {    		
//    			d.setName("~" + moduleName, SourceType.USER_DEFINED);
//    			d.setCallingConvention("__thiscall");
//    			d.setParentNamespace(classNamespace);
//    		} else {
//    			String prevComment = d.getComment();
//    			if (prevComment == null)
//    				prevComment = "";
//    			d.setComment(prevComment + "\nAdditionally: " + moduleName + "::~" + moduleName);
//    		}
//    		d = getFunctionAt(deleter);
//    		if (d == null) {
//    			d = createFunction(deleter, null);
//    		}
//    		d.setName("~~" + moduleName, SourceType.USER_DEFINED);
//    		d.setCallingConvention("__thiscall");
//    		d.setParentNamespace(classNamespace);
//    		ArrayList<Address> addresses = new ArrayList<Address>();
//    		while (si.hasNext()) {
//    			Symbol next = si.next();
//    			String mangledName = next.getName();
//    			Address symbolAddress = next.getAddress();
//    			if (mangledName.startsWith("_ZN3app8lua_bind") && getSymbolAt(symbolAddress).getName().startsWith(moduleName))
//    				addresses.add(symbolAddress);
//    		}
//    		// treat the symbol'd functions, the signatures might be fucked up /shrug
//    		for (Address address : addresses) {
//    			Function func = getFunctionAt(address);
//    			String virtFuncName = snakeCaseToPascalCase(func.getName());
//    			long vtableOffset = getVirtFuncOffset(address);
//    			Address virtAddress = vtableAddress.add(vtableOffset);
//    			Address virtFuncAddress = derefAddress(virtAddress);
//    			Function virtFunc = getFunctionAt(virtFuncAddress);
//    			if (virtFunc == null) {
//    				println(virtFuncAddress.toString());
//    				virtFunc = createFunction(virtFuncAddress, null);
//    				if (virtFunc == null)
//    					throw new Exception(String.format("%x", virtFuncAddress));
//    			}
//    			if (!(virtFunc.getParentNamespace() instanceof GhidraClass)) {    			
//    				virtFunc.setName(virtFuncName, SourceType.USER_DEFINED);
//    				virtFunc.setCallingConvention("__thiscall");
//    				virtFunc.setParentNamespace(classNamespace);
//    				Parameter[] params = func.getParameters();
//    				for (Parameter p : params) {
//    					if (!p.getFormalDataType().getDisplayName().equals("BattleObjectModuleAccessor *"))
//    						virtFunc.addParameter(p, SourceType.USER_DEFINED); // yes, yes, I know this is deprecated
//    				}
//    			} else {
//    				String prevComment = virtFunc.getComment();
//    				if (prevComment == null)
//    					prevComment = "";
//    				virtFunc.setComment(prevComment + "\nAdditionally: " + moduleName + "::" + virtFuncName);
//    			}
//    		}
//    		DataType vtable = generateVtableStruct(moduleName, vtableAddress, changeNonSymbolNamespace ? classNamespace : null);
//    		moduleStruct.replace(0, new Pointer64DataType(vtable), -1, "vtbl", null);
//    		program.getDataTypeManager().addDataType(moduleStruct, DataTypeConflictHandler.REPLACE_HANDLER);
//    	}
//TODO Add User Code Here
//    	Address vtableAddress = askAddress("Module VTable", "Enter the vtable address:");
//    	String moduleName = askString("Module Name", "Enter the name of the module:");
//    	int structSize = askInt("Struct Size", "Enter the size of the struct (approximate is fine):");
//    	boolean changeNonSymbolNamespace = askYesNo("Non-symbol'd Entries", "Would you like to change the parent namespace of functions which do not have an associated 'app::lua_bind' function?\nIf unsure, select 'No'.");
//    	println("Going to convert " + moduleName + " to a class with vtable at " + vtableAddress);
//    	println(snakeCaseToPascalCase("ControlModule__check_button_off_impl"));
    }

}
