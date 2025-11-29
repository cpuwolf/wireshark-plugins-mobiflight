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
field_group[2] = ProtoField.string("myusb.field2", "Field 2")
field_group[3] = ProtoField.string("myusb.field3", "Field 3")
field_group[4] = ProtoField.string("myusb.field4", "Field 4")
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

function mfsplit(inputString)
    local result = {}
    -- Pattern matches sequences of characters that are not ',' or ';'
    for match in inputString:gmatch("([^%;,]+)") do
        table.insert(result, match)
    end
    return result
end

-- Dissector function
function my_usb_proto.dissector(buffer, pinfo, tree)
    local subtree = tree:add(my_usb_proto, buffer(), "MobiFlight cpuwolf Protocol")

    local parts = mfsplit(buffer():string())
    for i, v in ipairs(parts) do
        print(v)
        if i == 1 then
            local num = tonumber(v)
            subtree:add(field_group[i], ParseCommandId(num) .. " (" .. v .. ")")
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
            pinfo.cols.info:set("USB MF (IN)") -- Set the protocol column in Wireshark
        else
            -- Handle Host to Device (OUT) direction
            pinfo.cols.info:set("USB MF (OUT)") -- Set the protocol column in Wireshark
        end
    end

    pinfo.cols.protocol = "USB MF"

    
end

-- Register the dissector to be called for USB bulk transfers
-- The '0xFF' is a placeholder and would need to be replaced with the relevant
-- value for the specific USB endpoint or interface.
DissectorTable.get("usb.bulk"):add(0xFF, my_usb_proto)
