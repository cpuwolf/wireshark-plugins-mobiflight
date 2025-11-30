-- Lua dissector for a MobiFlight USB protocol
-- Written by Wei Shuai <cpuwolf@gmail.com> 2025-Nov-29



-- Create a new protocol
local my_usb_proto = Proto("MobiFlight", "MobiFlight Serial Protocol")
-- Define a field extractor for the endpoint field
local usb_endpoint_field = Field.new("usb.endpoint_address")
local usb_irp_field = Field.new("usb.irp_info.direction")
local usb_irpid_field = Field.new("frame.number")

-- Define fields for the protocol
local field_group = {}
--field_group[1] = ProtoField.uint8("myusb.field1", "Field 1", base.HEX)
field_group[1] = ProtoField.string("MobiFlight.field1", "Command Id")

for i = 2, 10 do
    field_group[i] = ProtoField.string("MobiFlight.field" .. tostring(i), "Field" .. tostring(i))
end

field_group[11] = ProtoField.string("MobiFlight.deviceinfo", "deviceinfo")


-- Fields for merged packets
local f_merged_data = ProtoField.string("MobiFlight.data", "Merged Data")
local f_packet_count = ProtoField.uint16("MobiFlight.packet_count", "Packet Count")
local f_total_length = ProtoField.uint32("MobiFlight.total_length", "Total Length")
local f_sequence = ProtoField.uint16("MobiFlight.sequence", "Sequence Number")
local f_direction = ProtoField.string("MobiFlight.direction", "Direction")

field_group[15] = f_merged_data
field_group[16] = f_packet_count
field_group[17] = f_total_length
field_group[18] = f_sequence
field_group[19] = f_direction

my_usb_proto.fields = field_group


local CommandIdTable =
{
    [0] = "InitModule",
    [1] = "SetModule",
    [2] = "SetPin",
    [3] = "SetStepper",
    [4] = "SetServo",
    [5] = "Status",
    [6] = "EncoderChange",
    [7] = "ButtonChange",
    [8] = "StepperChange",
    [9] = "GetInfo",
    [10] = "Info",
    [11] = "SetConfig",
    [12] = "GetConfig",
    [13] = "ResetConfig",
    [14] = "SaveConfig",
    [15] = "ConfigSaved",
    [16] = "ActivateConfig",
    [17] = "ConfigActivated",
    [18] = "SetPowerSavingMode",
    [19] = "SetName",
    [20] = "GenNewSerial",
    [21] = "ResetStepper",
    [22] = "SetZeroStepper",
    [23] = "Retrigger",
    [24] = "ResetBoard",
    [25] = "SetLcdDisplayI2C",
    [26] = "SetModuleBrightness",
    [27] = "SetShiftRegisterPins",
    [28] = "AnalogChange",
    [29] = "InputShiftRegisterChange",
    [30] = "InputMultiplexerChange",
    [31] = "SetStepperSpeedAccel",
    [32] = "SetCustomDevice",
    [255] = "DebugPrint"
}

function ParseCommandId(NumCommandId)
    local str = CommandIdTable[NumCommandId]
    if str ~= nil then
        return str
    end
    return ""
end

local DeviceTypeTable =
{
    [0] = "NotSet",
    [1] = "Button",
    [2] = "EncoderSingleDetent",
    [3] = "Output",
    [4] = "LedModuleDeprecated",
    [5] = "StepperDeprecatedV1",
    [6] = "Servo",
    [7] = "LcdDisplay",
    [8] = "Encoder",
    [9] = "StepperDeprecatedV2",
    [10] = "ShiftRegister",
    [11] = "AnalogInput",
    [12] = "InputShiftRegister",
    [13] = "MultiplexerDriver",
    [14] = "InputMultiplexer",
    [15] = "Stepper",
    [16] = "LedModule",
    [17] = "CustomDevice",
}

function ParseDeviceType(NumDeviceType)
    local str = DeviceTypeTable[NumDeviceType]
    if str ~= nil then
        return str
    end
    return ""
end

function mfsplit(inputString)
    local result = {}
    -- Pattern matches sequences of characters that are not ',' or ';' or ':'
    for match in inputString:gmatch("([^%;,:]+)") do
        table.insert(result, match)
    end
    return result
end

function mfsplitdot(inputString)
    local result = {}
    -- Pattern matches sequences of characters that are not '.'
    for match in inputString:gmatch("([^%.]+)") do
        table.insert(result, match)
    end
    return result
end

function cmdid_10_handle(parts, pinfo, subtree)
    for i = 2, #parts do
        local v = parts[i]
        local field2tree = subtree:add(field_group[i], " (" .. v .. ")")
        local devicetypes = mfsplitdot(v)
        for j, dt in ipairs(devicetypes) do
            if j == 1 then
                local devicetypid = tonumber(dt)
                local devicetypestr = ParseDeviceType(devicetypid)
                field2tree:add(field_group[11], devicetypestr .. " (" .. dt .. ")")
            else
                field2tree:add(field_group[11], dt)
            end
        end
    end
end

function is_ascii_only(str)
    -- The pattern '[^%c%g%s]' matches any character that is NOT a control character (%c),
    -- a graphical character (%g), or a space character (%s).
    -- This effectively checks for characters outside the standard ASCII range (0-127).
    -- If such a character is found, string.find will return a position, otherwise nil.
    return not str:find('[^%c%g%s]')
end

-- Global table to store merged packets
local merged_sessions = {}
-- Session key generator
local function get_session_key(bus, device, endpoint, direction)
    return string.format("%d:%d:%d:%s", bus, device, endpoint, direction)
end


-- Packet merging function
local function merge_usb_packets(buffer, pinfo, tree)
    local is_complete_response = true
    local endpoint_value = usb_endpoint_field()
    local direction_in
    -- Check the direction bit (0x80)
    if endpoint_value ~= nil then
        direction_in = bit.band(endpoint_value.value, 0x80) == 0x80
    end
    local irp_dir = usb_irp_field().value
    local irp_id = usb_irpid_field().value

    -- Only process URB_BULK for IN
    if not direction_in or irp_dir == 0 then
        return nil
    end

    local hex_string = buffer:bytes():tohex()
    local buffer_len = buffer:bytes():len()
    if buffer(buffer_len - 2, 1):uint() == 0x0D and buffer(buffer_len - 1, 1):uint() == 0x0A then
        is_complete_response = true
    else
        is_complete_response = false
    end

    local packet_data = buffer():string()
    local session_key = irp_id

    local session = merged_sessions[session_key]
    table.insert(merged_sessions, {
        data = packet_data,
        timestamp = pinfo.abs_ts,
        number = irp_id
    })

    if is_complete_response then
        local merged_buffer = ""
        local merge_start_idx = 0
        local merge_end_idx

        -- get table end index
        for i, pkt in ipairs(merged_sessions) do
            if pkt.number == irp_id then
                merge_end_idx = i
                break
            end
        end
        -- get table start index
        if merge_end_idx > 1 then
            for i = merge_end_idx - 1, 1, -1 do
                if merged_sessions[i].data:match("\r\n$") ~= nil then
                    merge_start_idx = i + 1
                    break
                end
            end
        end

        for i = merge_start_idx, merge_end_idx do
            merged_buffer = merged_buffer .. merged_sessions[i].data
        end

        --print("Dumped buffer (hex): " .. tostring(merged_buffer))

        local merged_tree = tree:add(my_usb_proto, buffer(), "Merged USB Data")

        merged_tree:add(f_packet_count, #merged_sessions)
        --merged_tree:add(f_total_length, session.total_length)
        --merged_tree:add(f_sequence, session.sequence)
        --do return nil end

        -- Add the merged data
        print("Dumped Complete (hex): " .. merged_buffer)
        print("IRP (hex): " .. session_key)
        local data_item = merged_tree:add(f_merged_data, merged_buffer)
        --data_item:append_text(" (" .. session.total_length .. " bytes from " .. #session.packets .. " packets)")

        --session.collectondone = true
        -- Clear the session
        --merged_sessions[session_key] = nil
        return merged_buffer
    else

    end

    return nil
end

-- Dissector function
function my_usb_proto.dissector(buffer, pinfo, tree)
    local subtree = tree:add(my_usb_proto, buffer(), "MobiFlight cpuwolf Protocol")
    local cmdstring = ""
    local cmdidnum = 0
    local is_complete_response = true
    local endpoint_value = usb_endpoint_field()
    local direction_in
    -- Check the direction bit (0x80)
    if endpoint_value ~= nil then
        direction_in = bit.band(endpoint_value.value, 0x80) == 0x80
    end
    local irp_dir = usb_irp_field()

    if not is_ascii_only(buffer():string()) then
        -- MF communication uses all ascii
        return
    end


    local parts = mfsplit(buffer():string())

    local merged_buffer = merge_usb_packets(buffer, pinfo, tree)
    if merged_buffer then
        -- Set protocol column to show merged info
        --pinfo.cols.protocol = "USB MF MERGED"
        parts = mfsplit(merged_buffer)
    else
        parts = mfsplit(buffer():string())
    end

    for i, v in ipairs(parts) do
        if i == 1 then
            cmdidnum = tonumber(v)
            cmdstring = ParseCommandId(cmdidnum)
            if cmdstring == "" then
                -- No matches Command Id
            end
            subtree:add(field_group[i], cmdstring .. " (" .. v .. ")")
            -- Command Id == Info
            if cmdidnum == 10 and irp_dir == 1 then
                cmdid_10_handle(parts, pinfo, subtree)
                break
            end
        else
            -- check \r\n Ending
            if i == #parts and parts[i] == '\r\n' then
                is_complete_response = true
                subtree:add(field_group[i], v, "Field End" .. " (" .. v .. ")")
            else
                is_complete_response = false
                if irp_dir == 1 then
                else
                    subtree:add(field_group[i], v)
                end
            end
        end
    end

    -- Inside your dissector function:
    if direction_in then
        if not is_complete_response then
            pinfo.cols.info:set("USB MF (IN) " .. cmdstring .. " Conti...")
        else
            if merged_buffer then
                pinfo.cols.info:set("USB MF (IN) " .. cmdstring .. " Merged")
            else
            -- Handle Device to Host (IN) direction
            pinfo.cols.info:set("USB MF (IN) " .. cmdstring) -- Set the protocol column in Wireshark
            end
        end
    else
        -- Handle Host to Device (OUT) direction
        pinfo.cols.info:set("USB MF (OUT) " .. cmdstring) -- Set the protocol column in Wireshark
    end


    pinfo.cols.protocol = "USB MF"
end

-- Register the dissector to be called for USB bulk transfers
-- The '0xFF' is a placeholder and would need to be replaced with the relevant
-- value for the specific USB endpoint or interface.
DissectorTable.get("usb.bulk"):add(0xFF, my_usb_proto)
