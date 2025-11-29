-- Lua dissector for a MobiFlight USB protocol
-- Written by Wei Shuai <cpuwolf@gmail.com> 2025-Nov-29



-- Create a new protocol
local my_usb_proto = Proto("MF", "MobiFlight Serial Protocol")
-- Define a field extractor for the endpoint field
local usb_endpoint_field = Field.new("usb.endpoint_address")

-- Define fields for the protocol
local field_group = {}
--field_group[1] = ProtoField.uint8("myusb.field1", "Field 1", base.HEX)
field_group[1] = ProtoField.string("myusb.field1", "Command Id")

for i = 2, 10 do
    field_group[i] = ProtoField.string("myusb.field" .. tostring(i), "Field" .. tostring(i))
end

field_group[11] = ProtoField.string("myusb.deviceinfo", "deviceinfo")
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

-- Dissector function
function my_usb_proto.dissector(buffer, pinfo, tree)
    local subtree = tree:add(my_usb_proto, buffer(), "MobiFlight cpuwolf Protocol")
    local cmdstring = ""
    local cmdidnum = 0

    if not is_ascii_only(buffer():string()) then
        -- MF communication uses all ascii
        return
    end

    local parts = mfsplit(buffer():string())
    for i, v in ipairs(parts) do
        if i == 1 then
            cmdidnum = tonumber(v)
            cmdstring = ParseCommandId(cmdidnum)
            if cmdstring == "" then
                -- No matches Command Id
            end
            subtree:add(field_group[i], cmdstring .. " (" .. v .. ")")
            -- Command Id == Info
            if cmdidnum == 10 then
                cmdid_10_handle(parts, pinfo, subtree)
                break
            end
        else
            subtree:add(field_group[i], v)
        end
    end

    -- Inside your dissector function:
    local endpoint_value = usb_endpoint_field()
    if endpoint_value ~= nil then
        -- Check the direction bit (0x80)
        local direction_in = bit.band(endpoint_value.value, 0x80) == 0x80
        if direction_in then
            -- Handle Device to Host (IN) direction
            pinfo.cols.info:set("USB MF (IN) " .. cmdstring) -- Set the protocol column in Wireshark
        else
            -- Handle Host to Device (OUT) direction
            pinfo.cols.info:set("USB MF (OUT) " .. cmdstring) -- Set the protocol column in Wireshark
        end
    end

    pinfo.cols.protocol = "USB MF"
end

-- Register the dissector to be called for USB bulk transfers
-- The '0xFF' is a placeholder and would need to be replaced with the relevant
-- value for the specific USB endpoint or interface.
DissectorTable.get("usb.bulk"):add(0xFF, my_usb_proto)
