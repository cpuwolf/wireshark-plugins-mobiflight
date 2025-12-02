-- Lua dissector for a MobiFlight USB protocol
-- Written by Wei Shuai <cpuwolf@gmail.com> 2025-Nov-29
-- 
-- 这是一个 Wireshark 协议解析器，用于解析 MobiFlight USB 串口协议数据包
-- 该协议用于 MobiFlight 硬件设备与主机之间的通信

-- ============================================================================
-- 协议定义和字段提取器
-- ============================================================================

-- 创建新的协议对象
local my_usb_proto = Proto("MobiFlight", "MobiFlight Serial Protocol")

-- 定义 USB 字段提取器，用于获取 USB 协议相关信息
local usb_endpoint_field = Field.new("usb.endpoint_address")  -- USB 端点地址
local usb_irp_field = Field.new("usb.irp_info.direction")    -- USB IRP 方向
local usb_irpid_field = Field.new("frame.number")             -- 帧编号（用作会话标识）

-- ============================================================================
-- 协议字段定义
-- ============================================================================

local field_group = {}
-- 命令 ID 字段
field_group[1] = ProtoField.string("MobiFlight.field1", "Command Id")

-- 通用字段 2-10（用于存储命令参数）
for i = 2, 10 do
    field_group[i] = ProtoField.string("MobiFlight.field" .. tostring(i), "Field" .. tostring(i))
end

-- 设备信息相关字段
field_group[11] = ProtoField.string("MobiFlight.deviceinfo", "deviceinfo")   -- 设备类型信息
field_group[12] = ProtoField.string("MobiFlight.devicename", "devicename")   -- 设备名称
field_group[13] = ProtoField.string("MobiFlight.end", "Field End")            -- 字段结束标记

-- 合并数据包相关字段（用于处理分片传输的数据包）
local f_merged_data = ProtoField.string("MobiFlight.data", "Merged Data")           -- 合并后的完整数据
local f_packet_count = ProtoField.uint16("MobiFlight.packet_count", "Packet Count") -- 合并的包数量
local f_total_length = ProtoField.uint32("MobiFlight.total_length", "Total Length") -- 总长度（未使用）
local f_sequence = ProtoField.uint16("MobiFlight.sequence", "Sequence Number")       -- 序列号（未使用）
local f_direction = ProtoField.string("MobiFlight.direction", "Direction")          -- 传输方向（未使用）

field_group[15] = f_merged_data
field_group[16] = f_packet_count
field_group[17] = f_total_length
field_group[18] = f_sequence
field_group[19] = f_direction

-- 将字段组注册到协议对象
my_usb_proto.fields = field_group

-- ============================================================================
-- 命令 ID 映射表
-- ============================================================================

-- MobiFlight 协议支持的所有命令 ID 及其对应的命令名称
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

-- 接收方向的命令 ID 列表（从设备到主机）
-- 这些命令需要特殊处理，因为它们包含设备信息
local RxCommandIdTable = { 5, 6, 7, 8, 9, 10, 28 }

-- 为了优化查找性能，将列表转换为哈希表
local RxCommandIdSet = {}
for _, cmd_id in ipairs(RxCommandIdTable) do
    RxCommandIdSet[cmd_id] = true
end

-- ============================================================================
-- 工具函数：命令 ID 解析
-- ============================================================================

-- 将数字命令 ID 转换为可读的命令名称
-- @param NumCommandId: 数字形式的命令 ID
-- @return: 命令名称字符串，如果未找到则返回空字符串
function ParseCommandId(NumCommandId)
    local str = CommandIdTable[NumCommandId]
    if str ~= nil then
        return str
    end
    return ""
end

-- 检查命令 ID 是否为接收方向的命令（从设备到主机）
-- @param NumCommandId: 数字形式的命令 ID
-- @return: 如果是接收命令返回 true，否则返回 false
function IsRxCommandId(NumCommandId)
    return RxCommandIdSet[NumCommandId] == true
end

-- ============================================================================
-- 编码器变化类型映射表
-- ============================================================================

-- 编码器旋转方向类型（用于命令 ID 6: EncoderChange）
local EncodeChangeType =
{
    [0] = "LEFT",        -- 向左旋转
    [1] = "LEFT_FAST",   -- 快速向左旋转
    [2] = "RIGHT",       -- 向右旋转
    [3] = "RIGHT_FAST"   -- 快速向右旋转
}

-- 解析编码器变化类型
-- @param NumEncodeChangeType: 数字类型值
-- @return: 类型名称字符串，如果未找到则返回空字符串
function ParseEncodeChangeType(NumEncodeChangeType)
    local str = EncodeChangeType[NumEncodeChangeType]
    if str ~= nil then
        return str
    end
    return ""
end

-- ============================================================================
-- 设备类型映射表
-- ============================================================================

-- MobiFlight 支持的所有设备类型
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
    [17] = "CustomDevice",  -- 自定义设备
}

-- 解析设备类型
-- @param NumDeviceType: 数字设备类型值
-- @return: 设备类型名称字符串，如果未找到则返回空字符串
function ParseDeviceType(NumDeviceType)
    local str = DeviceTypeTable[NumDeviceType]
    if str ~= nil then
        return str
    end
    return ""
end

-- ============================================================================
-- 字符串处理工具函数
-- ============================================================================

-- 按分隔符（逗号、分号、冒号）分割字符串
-- 用于解析 MobiFlight 协议的命令参数
-- @param inputString: 输入字符串
-- @return: 分割后的字符串数组
function mfsplit(inputString)
    local result = {}
    -- 匹配不是 ','、';' 或 ':' 的字符序列
    for match in inputString:gmatch("([^%;,:]+)") do
        table.insert(result, match)
    end
    return result
end

-- 按点号（.）分割字符串
-- 用于解析设备信息（格式：设备类型.设备名称）
-- @param inputString: 输入字符串
-- @return: 分割后的字符串数组
function mfsplitdot(inputString)
    local result = {}
    -- 匹配不是 '.' 的字符序列
    for match in inputString:gmatch("([^%.]+)") do
        table.insert(result, match)
    end
    return result
end

-- 按指定分隔符分割字符串（更精确的实现）
-- 用于按 '\r\n' 分割合并后的数据包
-- @param s: 输入字符串
-- @param delimiter: 分隔符
-- @return: 分割后的字符串数组（不包含空字符串）
function mfgoodsplit(s, delimiter)
    local result = {}
    local from = 1
    local to
    while true do
        to = string.find(s, delimiter, from)
        if to then
            local str = string.sub(s, from, to - 1)
            if string.len(str) > 0 then
                table.insert(result, string.sub(s, from, to - 1))
            end
            from = to + string.len(delimiter)
        else
            local str = string.sub(s, from)
            if string.len(str) > 0 then
                table.insert(result, string.sub(s, from))
            end
            break
        end
    end
    return result
end

-- ============================================================================
-- 接收命令处理函数
-- ============================================================================

-- 处理接收方向的命令（从设备到主机）
-- 这些命令包含设备信息，需要特殊解析
-- @param parts: 分割后的命令参数数组
-- @param pinfo: 数据包信息对象
-- @param subtree: Wireshark 解析树节点
function cmdid_rx_handle(parts, pinfo, subtree)
    local cmdidnum = tonumber(parts[1])
    
    -- 遍历命令参数（从第二个参数开始，第一个是命令 ID）
    for i = 2, #parts do
        local v = parts[i]
        local field2tree
        local devicetypes = mfsplitdot(v)  -- 按点号分割设备信息

        -- 特殊处理：命令 ID 6 (EncoderChange) 的第三个参数是编码器变化类型
        if cmdidnum == 6 and i == 3 then
            local enctypestr = ParseEncodeChangeType(tonumber(v))
            field2tree = subtree:add(field_group[i], enctypestr .. " (" .. v .. ")")
        else
            field2tree = subtree:add(field_group[i], " (" .. v .. ")")
        end

        -- 解析设备类型和名称
        -- 格式通常是：设备类型.设备名称 或 设备类型.中间字段.设备名称
        for j, dt in ipairs(devicetypes) do
            if j == 1 then
                -- 第一个字段是设备类型 ID
                local devicetypid = tonumber(dt)
                local devicetypestr = ParseDeviceType(devicetypid)
                field2tree:add(field_group[11], devicetypestr .. " (" .. dt .. ")")
            else
                -- 最后一个字段是设备名称，其他是中间字段
                if j == #devicetypes then
                    field2tree:add(field_group[12], '"' .. dt .. '"')
                else
                    field2tree:add(field_group[11], dt)
                end
            end
        end
    end
end

-- ============================================================================
-- 数据验证函数
-- ============================================================================

-- 检查字符串是否只包含 ASCII 字符
-- MobiFlight 协议只使用 ASCII 字符，非 ASCII 字符表示不是 MobiFlight 数据包
-- @param str: 要检查的字符串
-- @return: 如果只包含 ASCII 字符返回 true，否则返回 false
function is_ascii_only(str)
    -- 模式 '[^%c%g%s]' 匹配任何不是控制字符(%c)、图形字符(%g)或空格字符(%s)的字符
    -- 这实际上检查的是标准 ASCII 范围(0-127)之外的字符
    -- 如果找到这样的字符，string.find 会返回位置，否则返回 nil
    return not str:find('[^%c%g%s]')
end

-- ============================================================================
-- 数据包合并功能
-- ============================================================================

-- 全局表：存储需要合并的数据包
-- 由于 USB 数据包可能被分片传输，需要将多个数据包合并成完整的消息
local merged_sessions = {}

-- 辅助函数：检查 USB 传输方向
-- @return: 如果是 IN 方向（设备到主机）返回 true，否则返回 false
local function is_direction_in()
    local endpoint_value = usb_endpoint_field()
    if endpoint_value ~= nil then
        -- 检查方向位 (0x80)，如果设置了表示 IN 方向
        return bit.band(endpoint_value.value, 0x80) == 0x80
    end
    return false
end

-- 辅助函数：检查数据包是否完整（以 \r\n 结尾）
-- @param buffer: 数据缓冲区
-- @return: 如果数据包完整返回 true，否则返回 false
local function is_complete_packet(buffer)
    local buffer_len = buffer:bytes():len()
    if buffer_len >= 2 then
        -- 检查最后两个字节是否为 0x0D 0x0A (\r\n)
        return buffer(buffer_len - 2, 1):uint() == 0x0D and 
               buffer(buffer_len - 1, 1):uint() == 0x0A
    end
    return false
end

-- 合并 USB 数据包
-- 当数据包被分片传输时，需要将多个数据包合并成完整的消息
-- @param buffer: 当前数据包缓冲区
-- @param pinfo: 数据包信息对象
-- @param tree: Wireshark 解析树
-- @return: 如果成功合并返回合并后的数据，否则返回 nil
local function merge_usb_packets(buffer, pinfo, tree)
    -- 只处理 IN 方向的数据包（从设备到主机）
    if not is_direction_in() then
        return nil
    end
    
    local irp_dir = usb_irp_field().value
    local irp_id = usb_irpid_field().value
    
    -- 只处理 URB_BULK IN 传输
    if irp_dir == 0 then
        return nil
    end

    local is_complete_response = is_complete_packet(buffer)
    local packet_data = buffer():string()
    
    -- 将当前数据包添加到合并会话中
    -- 使用数组存储，因为同一个 IRP ID 可能有多个数据包
    table.insert(merged_sessions, {
        data = packet_data,
        timestamp = pinfo.abs_ts,
        number = irp_id
    })

    -- 如果当前数据包是完整的（以 \r\n 结尾），则开始合并过程
    if is_complete_response then
        local merged_buffer = ""
        local merge_start_idx = 0
        local merge_end_idx

        -- 查找当前 IRP ID 对应的最后一个数据包索引
        for i, pkt in ipairs(merged_sessions) do
            if pkt.number == irp_id then
                merge_end_idx = i
                break
            end
        end
        
        -- 向前查找合并起始位置（找到上一个以 \r\n 结尾的数据包）
        if merge_end_idx and merge_end_idx > 1 then
            for i = merge_end_idx - 1, 1, -1 do
                if merged_sessions[i].data:match("\r\n$") ~= nil then
                    merge_start_idx = i + 1
                    break
                end
            end
        end

        -- 如果只有一个数据包，不需要合并
        if not merge_end_idx or merge_end_idx - merge_start_idx < 1 then
            return nil
        end

        -- 合并从起始索引到结束索引的所有数据包
        for i = merge_start_idx, merge_end_idx do
            merged_buffer = merged_buffer .. merged_sessions[i].data
        end

        -- 在解析树中添加合并后的数据
        local merged_tree = tree:add(my_usb_proto, buffer(), "Merged USB Data")
        merged_tree:add(f_packet_count, merge_end_idx - merge_start_idx + 1)
        merged_tree:add(f_merged_data, merged_buffer)
        
        -- 调试输出（可选）
        print("Dumped Complete (hex): " .. merged_buffer)
        print("IRP ID: " .. irp_id)
        
        return merged_buffer
    end

    -- 如果数据包不完整，返回 nil（等待更多数据包）
    return nil
end

-- ============================================================================
-- 主解析函数
-- ============================================================================

-- 解析 MobiFlight 协议数据包
-- @param buffer: 数据缓冲区
-- @param subtree: Wireshark 解析树节点
-- @param parts: 已分割的命令参数数组
-- @param pinfo: 数据包信息对象
function my_parser(buffer, subtree, parts, pinfo)
    local cmdstring = ""
    local cmdidnum = 0
    local direction_in = is_direction_in()
    local irp_dir = usb_irp_field().value
    local is_complete_response = is_complete_packet(buffer)

    -- 解析命令参数
    for i, v in ipairs(parts) do
        if i == 1 then
            -- 第一个参数是命令 ID
            cmdidnum = tonumber(v) or 0
            cmdstring = ParseCommandId(cmdidnum)
            
            -- 在解析树中添加命令 ID
            subtree:add(field_group[i], cmdstring .. " (" .. v .. ")")
            
            -- 如果是接收方向的命令（从设备到主机），使用特殊处理函数
            if irp_dir == 1 and IsRxCommandId(cmdidnum) then
                cmdid_rx_handle(parts, pinfo, subtree)
                break
            end
        else
            -- 处理其他参数
            if i == #parts and parts[i] == '\r\n' then
                -- 最后一个参数是结束标记
                subtree:add(field_group[13], "", v)
            else
                -- 对于 OUT 方向的命令，添加参数字段
                if irp_dir ~= 1 then
                    subtree:add(field_group[i], "", v)
                end
            end
        end
    end

    -- 设置 Wireshark 信息列显示
    if direction_in then
        -- IN 方向：从设备到主机
        if not is_complete_response then
            pinfo.cols.info:set("USB MF (IN) " .. cmdstring .. " Conti...")
        else
            pinfo.cols.info:set("USB MF (IN) " .. cmdstring)
        end
    else
        -- OUT 方向：从主机到设备
        pinfo.cols.info:set("USB MF (OUT) " .. cmdstring)
    end

    -- 设置协议列
    pinfo.cols.protocol = "USB MF"
end

-- ============================================================================
-- Wireshark 解析器主函数
-- ============================================================================

-- Wireshark 会为每个匹配的数据包调用此函数
-- @param buffer: 数据包缓冲区
-- @param pinfo: 数据包信息对象
-- @param tree: Wireshark 解析树根节点
function my_usb_proto.dissector(buffer, pinfo, tree)
    -- 创建协议解析子树
    local subtree = tree:add(my_usb_proto, buffer(), "MobiFlight Protocol")
    
    -- 验证数据包是否为 ASCII 字符（MobiFlight 协议只使用 ASCII）
    if not is_ascii_only(buffer():string()) then
        return  -- 不是 MobiFlight 数据包，直接返回
    end

    local parts
    local merged_buffer = merge_usb_packets(buffer, pinfo, tree)
    
    if merged_buffer then
        -- 处理合并后的数据包
        -- 合并后的数据可能包含多行，每行以 \r\n 分隔
        local lines = mfgoodsplit(merged_buffer, '\r\n')
        for i, ln in ipairs(lines) do
            -- 按分隔符分割每行数据
            parts = mfsplit(ln .. '\r\n')
            my_parser(buffer, subtree, parts, pinfo)
            pinfo.cols.info:append(" Merged")
        end
    else
        -- 处理单个数据包（未合并）
        parts = mfsplit(buffer():string())
        my_parser(buffer, subtree, parts, pinfo)
    end
end

-- ============================================================================
-- 注册解析器
-- ============================================================================

-- 将解析器注册到 USB bulk 传输解析表
-- 0xFF 是占位符，需要根据实际的 USB 端点或接口值进行替换
DissectorTable.get("usb.bulk"):add(0xFF, my_usb_proto)
