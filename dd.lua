-- USB IN URB Bulk Reassembler - Complete working version
local usb_bulk_reassembler = Proto("usb_bulk_reass", "USB IN URB Bulk Reassembler")

-- Fields
local f_reassembled_data = ProtoField.bytes("usb_bulk_reass.data", "Reassembled Data")
local f_message_length = ProtoField.uint32("usb_bulk_reass.message_length", "Message Length")
local f_fragment_count = ProtoField.uint16("usb_bulk_reass.fragment_count", "Fragment Count")
local f_endpoint = ProtoField.uint8("usb_bulk_reass.endpoint", "Endpoint", base.HEX)
local f_transfer_id = ProtoField.uint32("usb_bulk_reass.transfer_id", "Transfer ID")

usb_bulk_reassembler.fields = {
    f_reassembled_data, f_message_length, f_fragment_count, f_endpoint, f_transfer_id
}

-- Reassembly state
local reassembly_sessions = {}
local current_transfer_id = 0

-- USB URB detection
local function is_likely_usb_urb(buffer)
    if buffer:len() < 16 then return false end

    local urb_type = buffer(0, 1):uint()
    local valid_types = { 0x1b }

    for _, v in ipairs(valid_types) do
        if urb_type == v then return true end
    end

    return false
end

local function is_in_bulk_complete(buffer)
    if buffer:len() < 16 then return false end

    local urb_type = buffer(0x0, 1):uint()
    local endpoint = buffer(0x15, 1):uint()
    local transfer_type = buffer(0x16, 1):uint()
    local irp = buffer(0x10, 1):uint()
    local direction = bit.band(endpoint, 0x80)

    return (urb_type == 0x1b and direction == 0x80 and transfer_type == 0x03 and irp == 0x1)
end

local function get_usb_transfer_info(buffer)
    return {
        bus = buffer(0x11, 2):uint(),
        device = buffer(0x13, 2):uint(),
        endpoint = buffer(0x15, 1):uint()
    }
end

local function extract_urb_data(buffer)
    local data_offset = 0x1B

    if buffer:len() <= data_offset then
        return nil, 0
    end

    local data_length = buffer:len() - data_offset
    return buffer(data_offset, data_length):bytes(), data_length
end

-- Reassembly logic
local function reassemble_bulk_in_packets(buffer, pinfo, tree)
    if not is_in_bulk_complete(buffer) then return nil end

    local usb_info = get_usb_transfer_info(buffer)
    local data, data_len = extract_urb_data(buffer)
    if not data then return nil end

    local session_key = string.format("%d:%d:0x%02x", usb_info.bus, usb_info.device, usb_info.endpoint)

    if not reassembly_sessions[session_key] then
        current_transfer_id = current_transfer_id + 1
        reassembly_sessions[session_key] = {
            buffer = ByteArray.new(),
            fragment_count = 0,
            total_length = 0,
            transfer_id = current_transfer_id,
            max_packet_size = 64
        }
    end

    local session = reassembly_sessions[session_key]
    session.buffer:append(data)
    session.fragment_count = session.fragment_count + 1
    session.total_length = session.total_length + data_len

    if data_len > session.max_packet_size then
        session.max_packet_size = data_len
    end

    -- Check for transfer completion (short packet)
    local is_complete = (data_len < session.max_packet_size)

    if is_complete then
        local reassembly_tree = tree:add(usb_bulk_reassembler, buffer(), "USB IN URB Bulk Reassembly")

        reassembly_tree:add(f_endpoint, usb_info.endpoint)
        reassembly_tree:add(f_fragment_count, session.fragment_count)
        reassembly_tree:add(f_message_length, session.total_length)
        reassembly_tree:add(f_transfer_id, session.transfer_id)

        local reassembled_tvb = session.buffer:tvb("Reassembled Data")
        reassembly_tree:add(f_reassembled_data, reassembled_tvb:range(), "Reassembled Payload")

        -- Parse the data
        --parse_reassembled_data(reassembled_tvb, reassembly_tree)

        pinfo.cols.protocol = "USB-BULK-IN"
        pinfo.cols.info:set(string.format("Transfer %d: %d bytes", session.transfer_id, session.total_length))

        reassembly_sessions[session_key] = nil
        return reassembled_tvb
    else
        -- Show progress
        local progress_tree = tree:add(usb_bulk_reassembler, buffer(), "Bulk IN Reassembly (In Progress)")
        progress_tree:add(f_fragment_count, session.fragment_count)
        progress_tree:add(f_message_length, session.total_length)
        progress_tree:add(f_transfer_id, session.transfer_id)
    end

    return nil
end

local function parse_reassembled_data(data_tvb, parent_tree)
    local data_len = data_tvb:len()
    local analysis_tree = parent_tree:add(usb_bulk_reassembler, data_tvb(), "Data Analysis")

    analysis_tree:add("Total Size: " .. data_len .. " bytes")

    -- Simple hex preview for small data
    if data_len <= 32 then
        analysis_tree:add("Hex: " .. data_tvb:bytes():tohex())
    end

    -- Try to detect content type
    local text_chars = 0
    local sample_size = math.min(64, data_len)

    for i = 0, sample_size - 1 do
        local byte = data_tvb(i, 1):uint()
        if byte >= 32 and byte <= 126 then
            text_chars = text_chars + 1
        end
    end

    if (text_chars / sample_size) > 0.8 then
        analysis_tree:add("Content: Likely text")
    else
        analysis_tree:add("Content: Likely binary")
    end
end

-- Main dissector function
function usb_bulk_reassembler.dissector(buffer, pinfo, tree)
    
    -- Only process packets that look like USB URB
    if not is_likely_usb_urb(buffer) then return end

    print("USB Bulk Reassembler")

    -- Try to reassemble bulk IN packets
    local result = reassemble_bulk_in_packets(buffer, pinfo, tree)
end

-- Registration - Try multiple methods
local function register_dissector()
    --[[ Method 1: Try USB tables
    local usb_tables = { "usb", "usb.device", "usb.bulk", "usbmon", "usb.data" }
    for _, table_name in ipairs(usb_tables) do
        local dissector_table = DissectorTable.get(table_name)
        if dissector_table then
            dissector_table:add(0, usb_bulk_reassembler)
            print("USB Bulk Reassembler registered to: " .. table_name)
            return
        end
    end
    ]]--

    -- Method 2: Register as post-dissector (will run on all packets)
    register_postdissector(usb_bulk_reassembler)
    print("USB Bulk Reassembler registered as post-dissector")
end

-- Auto-register
register_dissector()
