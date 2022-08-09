local control_commands = {
    [0xf0] = "Set Debug State",
    [0xf1] = "Set Run State",
    [0xf3] = "Get Status",
    [0xf4] = "Set Breakpoint List",
    [0xf5] = "Get Function Pointer",
	
    [0x10] = "Tag Values",
    [0x11] = "Set Tag Value",
    [0xac] = "Tag Count",
    [0x0a] = "Get Tag Info",
	
    [0x14] = "Get Device Information",
	
    [0x40] = "Get Error State????",
	
    [0x91] = "Set Time",
    [0x92] = "Get Time"
}

local run_states = {
    [0x01] = "Run",
    [0x02] = "Stop/Pause",
    [0x03] = "Step Into",
    [0x04] = "Step Out",
    [0x05] = "Step Over",
    [0x06] = "Reset"
}

local run_mode = {
    [0x01] = "Normal",
    [0x02] = "Debug"
}

local tag_size = {
    [0x01] = "1-Bit",
    [0x11] = "8-Bit"
}


velo_prot = Proto("velocio",  "Velocio Protocol")

local vCapData = ProtoField.bytes("usb.capdata", "Captured Data")
local vMalformed = ProtoField.none("velocio.malformed", "Malformed Packet")
local vUnknown = ProtoField.none("velocio.unknown", "Rest Unknown")
local vHeader = ProtoField.uint32("velocio.header", "Header", base.HEX)
local vLength = ProtoField.uint8("velocio.length", "Length", base.DEC)
local vCommand  = ProtoField.uint8("velocio.cmd", "Command ID", base.HEX, control_commands)
local vSend = ProtoField.none("velocio.send", "Send/Request")
local vAck = ProtoField.none("velocio.ack", "ACK/Response")
local vExecCmd  = ProtoField.uint8("velocio.cmd_exec", "Run State", base.HEX, run_states)
local vTag2Bytes = ProtoField.uint16("velocio.t2b", "First Bytes", base.HEX)
local vTagIndex = ProtoField.uint16("velocio.tag_index", "Tag Index", base.DEC)
local vTagCount = ProtoField.uint16("velocio.tag_count", "Tag Count", base.DEC)
local vBreakpointData = ProtoField.bytes("velocio.breakpoint_data", "Breakpoint Data")
local vTimeData = ProtoField.relative_time("velocio.time", "Time")
local vErrors = ProtoField.uint16("velocio.errors", "Error Data", base.HEX)
local vRunType  = ProtoField.uint8("velocio.run_type", "Run Type", base.HEX, run_mode)
local vFunctionPointer  = ProtoField.uint32("velocio.function_pointer", "Function Pointer", base.DEC)
local vUnknownByte = ProtoField.uint8("velocio.ubqm", "Unknown Byte", base.HEX)
local vTagName = ProtoField.string("velocio.tag_name", "Tag Name")
local vTagSize  = ProtoField.uint8("velocio.tag_size", "Tag Size", base.HEX, tag_size)


velo_prot.fields = {vCapData, vMalformed, vUnknown, vHeader, vLength, vCommand, vSend,
 vAck, vExecCmd, vTag2Bytes, vTagIndex, vTagCount, vBreakpointData, vTimeData, vErrors,
 vRunType, vFunctionPointer, vUnknownByte, vTagName, vTagSize}

function velo_prot.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length < 4 then return 0 end
   pinfo.cols.protocol = velo_prot.name
   if buffer(0,4):uint() ~= 0x56ffff00 then return 0 end
   tree:add(vCapData, buffer())
   local subtree = tree:add(velo_prot, buffer(), "Velocio Protocol Data")
   local lenBuf = buffer(4, 1)
   if lenBuf:uint() ~= length then
      subtree:add(vMalformed, buffer(0))
	  return
   end
   subtree:add(vHeader, buffer(0, 4))
   subtree:add(vLength, lenBuf)
   local vType = buffer(5, 1)
   local ssub = subtree:add(vCommand, vType)
   local isAck = false
   local isKnown = false
   local index = 6
   
   for k, x in pairs(control_commands) do
      if vType:uint() == k then
	     isKnown = true
	  end
   end
   if length >= 7 then
      local bi6 = buffer(index, 1)
      if bi6:uint() == 0x06 and not (vType:uint() == 0xf1 and length == 7) then
         isAck = true
         subtree:add(vAck, bi6)
         index = index + 1
      end
   end
   if not isKnown and index + 1 < length then
      subtree:add(vUnknown, buffer(index))
      return
   end
   
   --Get Tag Info
   if vType:uint() == 0x0a and isAck then
      subtree:add(vTagIndex, buffer(index, 2))
	  index = index + 2
	  subtree:add(vTagName, buffer(index, 16))
	  index = index + 16
   end
   
   --Get Tag Info
   if vType:uint() == 0x11 then
      if not isAck then 
	     subtree:add(vSend, buffer(index, 1))
		 index = index + 1
	     subtree:add(vTagIndex, buffer(index, 2))
		 index = index + 2
      end
   end
   
   --Get Error Info
   if vType:uint() == 0x40 and isAck then
      subtree:add(vErrors, buffer(index, 2))
	  index = index + 2
   end
   
   -- Set Time
   if vType:uint() == 0x91 and not isAck then
      subtree:add(vTimeData, buffer(index, 4))
	  index = index + 4
   end
   
   --Time Return
   if vType:uint() == 0x92 and isAck then
      subtree:add(vTimeData, buffer(index, 4))
	  index = index + 4
   end
   
   --Get Tag Count
   if vType:uint() == 0xac and isAck then
      subtree:add(vTagCount, buffer(index + 1, 2))
	  index = index + 3
   end
   
   --Run state
   if vType:uint() == 0xf1 then
      subtree:add(vExecCmd, buffer(index, 1))
	  index = index + 1
   end
   
   --Get Run Status
   if vType:uint() == 0xf3 and isAck then
      subtree:add(vRunType, buffer(index, 1))
	  index = index + 1
	  subtree:add(vExecCmd, buffer(index, 1))
	  index = index + 1
	  subtree:add(vFunctionPointer, buffer(index, 4))
	  index = index + 4
   end
   
   --Breakpoint
   if vType:uint() == 0xf4 then
      if not isAck then 
	     subtree:add(vSend, buffer(index, 1))
		 index = index + 1
      end
      subtree:add(vTag2Bytes, buffer(index, 2))
	  index = index + 2
	  subtree:add(vBreakpointData, buffer(index))
	  index = length - 1
   end
   
   --Get Run Status
   if vType:uint() == 0xf5 and isAck then
      subtree:add(vUnknownByte, buffer(index, 1))
	  index = index + 1
	  subtree:add(vFunctionPointer, buffer(index, 4))
	  index = index + 4
   end
   
   if index + 1 < length then
      subtree:add(vUnknown, buffer(index))
   end

end

--bInterfaceClass, thx WireShark for having no documentation on this
DissectorTable.get("usb.bulk"):add(0x0a, velo_prot)