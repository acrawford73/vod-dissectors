-- --------------------------------------
-- Copyright 2016-2019 Charter Communications. All rights reserved.
-- This program is property of Charter Communications and is to be used by Charter employees only.
-- DO NOT copy or distribute by any means without written permission from Charter Communications.
-- --------------------------------------
-- DSM-CC SSP Dissector
-- Client-side Messages
-- UDP Ttransport
-- 
-- script-name: twcssp.lua
-- Version 0.28
--
-- 2017 Anthony Crawford
-- Advanced Engineering, Charter Communications
-- Additional recommendations provided by Active Video Networks and Time Warner Cable
-- 
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1
local default_settings =
{
    debug_level  = DEBUG,
    port         = 13819,
    heur_enabled = true
}

local args={...}
if args and #args > 0 then
    for _, arg in ipairs(args) do
        local name, value = arg:match("(.+)=(.+)")
        if name and value then
            if tonumber(value) then
                value = tonumber(value)
            elseif value == "true" or value == "TRUE" then
                value = true
            elseif value == "false" or value == "FALSE" then
                value = false
            elseif value == "DISABLED" then
                value = debug_level.DISABLED
            elseif value == "LEVEL_1" then
                value = debug_level.LEVEL_1
            elseif value == "LEVEL_2" then
                value = debug_level.LEVEL_2
            else
                error("invalid commandline argument value")
            end
        else
            error("invalid commandline argument syntax")
        end
        default_settings[name] = value
    end
end

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end
        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end

reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------
-- Check the version and error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end
-- Verify the presence of ProtoExpert class in Wireshark
assert(ProtoExpert.new, "This version of Wireshark does not have the ProtoExpert class, use latest 1.11.3 or higher")

----------------------------------------

-- EDIT STARTING HERE --

----------------------------------------

local discriminator = {
    -- 11 is first byte of DSM-CC packet
    [17] = "MPEG-2 DSM-CC"
}
-- types of dsmcc messages
local dsmcc_types = {
    [0] = "ISO/IEC 13818-6 DSM-CC Reserved",
    [1] = "ISO/IEC 13818-6 DSM-CC U-N Configuration",
    [2] = "ISO/IEC 13818-6 DSM-CC U-N Session",
    [3] = "ISO/IEC 13818-6 DSM-CC Download",
    [4] = "ISO/IEC 13818-6 DSM-CC Switched Digital Broadcast",
    [5] = "ISO/IEC 13818-6 DSM-CC U-N Passthrough",
    [128] = "User Defined"
}
local message_types = {
    -- client and srm
    [16400] = "Client Session Setup Request",           -- 0x4010
    [16401] = "Client Session Setup Confirm",           -- 0x4011
    [16416] = "Client Session Release Request",         -- 0x4020
    [16417] = "Client Session Release Confirm",         -- 0x4021
    [16418] = "Client Session Release Indication",      -- 0x4022
    [16419] = "Client Session Release Response",        -- 0x4023
    [16480] = "Client Status Request",                  -- 0x4060
    [16481] = "Client Status Confirm",                  -- 0x4061
    [16514] = "Client Proceeding Indication",           -- 0x4082
    [16560] = "Client Session InProgress Request",      -- 0x40b0
    -- server and srm
    [32786] = "Server Session Setup Indication",        -- 0x8012
    [32787] = "Server Session Setup Response",          -- 0x8013
    [32800] = "Server Release Request",                 -- 0x8020
    [32801] = "Server Release Confirm",                 -- 0x8021
    [32802] = "Server Release Indication",              -- 0x8022
    [32803] = "Server Release Response",                -- 0x8023
    [32816] = "Server Add Resource Request",            -- 0x8030
    [32817] = "Server Add Resource Confirm",            -- 0x8031
    [32848] = "Server Continuous Feed Session Request", -- 0x8050
    [32849] = "Server Continuous Feed Session Confirm", -- 0x8051
    [32864] = "Server Status Request",                  -- 0x8060
    [32865] = "Server Status Confirm",                  -- 0x8061
    [32898] = "Server Session Proceeding Indication",   -- 0x8082
    [32944] = "Server Session InProgress Request"       -- 0x80b0
}
-- message id
local message_discriminator = {
    [0] = "ISO/IEC 13818-6 Reserved",
    [1] = "Client and Network",
    [2] = "Server and Network",
    [3] = "ISO/IEC Reserved"
}
local message_scenario = {
    [0] = "ISO/IEC 13818-6 Reserved",
    [1] = "Session Setup",
    [2] = "Session Release",
    [3] = "Add Resource",
    [4] = "Delete Resource",
    [5] = "Continuous Feed Session Setup",
    [6] = "Status",
    [7] = "Reset",
    [8] = "Session Proceeding",
    [9] = "Session Connect",
    [10] = "Session Transfer",
    [11] = "Session In-Progress"
}
local message_type = {
    [0] = "Request",
    [1] = "Confirm",
    [2] = "Indication",
    [3] = "Response"
}
--adaptation
local adaptation_type = {
    [0] = "ISO/IEC 1318-6 Reserved",
    [1] = "DSM-CC Conditional Access",
    [2] = "DSM-CC User ID",
    [3] = "ISO/IEC 1318-6 Reserved"
}
-- qam modulation formats
local mod_format = {
    [6] = "QAM16",
    [7] = "QAM32",
    [8] = "QAM64",
    [12] = "QAM128",
    [16] = "QAM256"
}
-- ssp reason codes
local reason_codes = {
    [0] = "RsnOK - Proceeding normally",
    [1] = "RsnNormal - Normal conditions for releasing session",
    [2] = "RsnClProcError - Client detected procedure error",
    [3] = "RsnNeProcError - SRM detected procedure error",
    [4] = "RsnSeProcError - Server detected procedure error",
    [5] = "RsnClFormatError - Client detected invalid format",
    [6] = "RsnNeFormatError - SRM detected invalid format",
    [7] = "RsnSeFormatError - Server detected Invalid format",
    [8] = "RsnNeConfigCnf - SRM confirmed configuration sequence (Client must respond)",
    [9] = "RsnScTranRefuse - Session transfer was refused by destination Server",
    [10] = "RsnSeForwardOvl - Session forwarding is due to overload conditions",
    [11] = "RsnSeForwardMnt - Session forwarding is due to overload maintenance conditions",
    [12] = "RsnSeForwardUncond - Session forwarding is sent as an unconditional request",
    [13] = "RsnSeRejResource - Server rejected the assigned resources",
    [14] = "RsnNeBroadcast - Message is being broadcast and does not require a response",
    [15] = "RsnSeServiceTransfer - Server indicates that the client will establish a session to another serverID based on the context provided in the PrivateData() section",
    [16] = "RsnClNoSession - Client indicates that the sessionId is not active",
    [17] = "RsnSeNoSession - Server indicates that the sessionId is not active",
    [18] = "RsnNeNoSession - SRM indicates that the sessionId is not active",
    [19] = "RsnRetrans - Retransmitted message",
    [20] = "RsnNoTransaction - Message received without transactionId",
    [21] = "RsnClNoResource - Requested resource is not supported",
    [22] = "RsnClRejResource - Client rejected the assigned resources",
    [23] = "RsnNeRejResource - SRM rejected the resources assigned by the Server",
    [24] = "RsnNeTimerExpired - Message sent due to expired timer",
    [25] = "RsnClSessionRelease - Client initiated session release",
    [26] = "RsnSeSessionRelease - Server initiated session release",
    [27] = "RsnNeSessionRelease - Network initiated session release",
    -- Arris CMM specific reason codes
    [32769] = "SE_ENTITLEMENT_EXPIRED",
    [32770] = "SE_COULD_NOT_BILL",
    [32771] = "SE_CANCELLED_BY_GUI",
    [32772] = "SE_SESSION_PING_EXPIRED",
    [32773] = "SE_DUPLICATE_SESSION",
    [32774] = "SE_ODA_EXCEPTION",
    [32775] = "SE_MOVIE_NOT_FOUND",
    [32776] = "SE_RTSP_DEAD_SESSION",
    -- Openstream specific reason codes
    [33104] = "RsnItvAdmin - SRM or SGW initiated suspend due to action by Administrator",
    [33105] = "RsnItvSetupTimeout - SRM initiated suspend due to Setup Timer expired in SRM",
    [33106] = "RsnItvKeepAliveTimeout - SRM initiated suspend due to missed STB keep alives",
    [33107] = "RsnItvERMAdmin - SRM initiated suspend due to request by external resource of policy manager",
    [33108] = "RsnItvReconcile - SRM initiated suspend due to a mismatch in session lists"
}
-- ssp response codes
local response_codes = {
    [0] = "RspOK - Request completed without errors",
    [1] = "RspClNoSession - Client rejected, invalid session id",
    [2] = "RspNeNoCalls - SRM unable to accept new calls",
    [3] = "RspNeInvalidClient - SRM rejected invalid client id",
    [4] = "RspNeInvalidServer - SRM rejected invalid server id",
    [5] = "RspNeNoSession - SRM rejected invalid session id",
    [6] = "RspSeNoCalls - Server unable to accept new calls or NAG check failed",
    [7] = "RspSeInvalidClient - Server rejected invalid client id",
    [8] = "RspSeNoService - Server rejected, service not available",
    [9] = "RspSeNoCFS - Server rejected the request because the requested Continuous Feed Session could not be found",
    [10] = "RspClNoResponse - Network timed out before the Client responded to an indication message",
    [11] = "RspSeNoResponse - Network timed out before the Server responded to an indication message",
    [12] = "Reserved",
    [13] = "Reserved",
    [14] = "Reserved",
    [15] = "Reserved",
    [16] = "RspSeNoSession - Server timed out, invalid session id",
    [17] = "RspNeResourceContinue - Resource request completed with no errors, however an indicated resource was assigned an alternate value by the Network",
    [18] = "RspNeResourceFailed - Resource request failed due to SRM was unable to assign requested resources",
    [19] = "RspNeResourceOK - Requested command completed with no errors",
    [20] = "RspResourceNegotiate - Network was able to complete request but assigned alternative values to a negotiation field",    
    [21] = "RspClSessProceed - Network is waiting on a response from the Server",
    [22] = "RspClUnkRequestID - Client received a message containing an unknown resourceRequestId",
    [23] = "RspClNoResource - Client rejected session setup because it was unable to use the assigned resources",
    [24] = "RspClNoCalls - Client rejected session setup because it was not accepting calls at that time",
    [25] = "RspNoResource - Network is unable to assign one or more resources to a session",
    [26] = "Reserved",
    [27] = "Reserved",
    [28] = "Reserved",
    [29] = "Reserved",
    [30] = "Reserved",
    [31] = "Reserved",
    [32] = "RspSeNoResource - Server unable to complete session setup due to missing resource",
    [33] = "RspSeRejResource - Server rejected the assigned resources",
    [34] = "RspClProcError - Procedure error detected at the Client",
    [35] = "RspNeProcError - Procedure error detected at the Network",
    [36] = "RspSeProcError - Procedure error detected at the Server",
    [37] = "Reserved",      
    [38] = "RspNeFormatError - Network detected a format error",    
    [39] = "RspSeFormatError - Server detected a format error",
    [40] = "RspSeForwardOvl - Session forwarding due to overload conditions",
    [41] = "RspSeForwardMnt - Session forwarding due to overload maintenance conditions",
    [42] = "RspClRejResource - Client rejected resource assigned to session",
    [43] = "Reserved",
    [44] = "Reserved",
    [45] = "Reserved",
    [46] = "Reserved",
    [47] = "Reserved",
    [48] = "RspSeForwardUncond - Session forwarding sent as an unconditional request",
    [49] = "RspNeTransferFailed - Session transfer failed at the Network",
    [50] = "RspClTransferReject - Session transfer failed at the Client",
    [51] = "RspSeTransferReject - Session transfer failed at the Server",
    [52] = "RspSeTransferResource - Server rejected the session transfer due to insufficient resource",
    [53] = "RspResourceCompleted - Server accepted the resources assigned by the Network",
    [54] = "RspForward - Server requesting a Session Forward",
    [55] = "RspNeForwardFailed - Network is unable to process a Session Forward",
    [56] = "RspClForwarded - Session was forwarded to the indicated clientId",
    [57] = "Reserved",
    [58] = "Reserved",
    [59] = "Reserved",
    [60] = "Reserved",
    [61] = "Reserved",
    [62] = "Reserved",
    [63] = "Reserved",
    [64] = "Reserved",
    [65] = "RspSeTransferNoRes - Server could not get enough resources, so it rejected the transfer",
    [66] = "RspNeNotOwner - An action was requested on a session by a User that was not the owner of that session"
}
-- related to cssr and cssc backoffice side, user defined resource F001
local transmission_systems = {
    [0] = "Unknown Transmission System",
    [1] = "SADVB Transmission System",
    [2] = "GI Transmission System"
}
local fec = {
    [0] = "FEC Transmission System",
    [1] = "FEC DAVIC"
}
local purchase_type_request = {
    [1] = "Purchase",
    [2] = "View Already Purchased",
    [3] = "Purchase SVOD Package",
    [4] = "Authorization List",
    [5] = "Rental List",
    [6] = "Preview",
    [8] = "STB Error Report",
    [9] = "Rental Deletion",
    [11] = "Service Name",
    [12] = "Service Gateway"
}
local purchase_type_response = {
    [2] = "Subscription Authorization List",
    [3] = "Current Rental List",
    [5] = "Purchase Response",
    [6] = "View Response"
}
local res_value_type = {
    [0] = "Reserved",
    [1] = "Single",
    [2] = "List",
    [3] = "Range"
}
local response_failure_code = {
    [1] = "Movie Unavailable", 
    [2] = "Bandwidth Unavailable", 
    [3] = "System Error", 
    [4] = "Purchase Denied", 
    [5] = "Rental Not Found", 
    [6] = "Linear Service Not Authorized", 
    [7] = "On Demand Service Not Authorized", 
    [8] = "Failed to return rental list", 
    [9] = "Failed to store STB error", 
    [10] = "Failed to delete rental", 
    [11] = "Failed to find rental", 
    [12] = "Request data unparsable", 
    [13] = "Server Processing Error"
}
local physical_direction = {
    [0] = "Downstream (Server to Client)",
    [1] = "Upstream (Client to Server)"
}
local resource_status = {
    [0] = "Reserved",
    [1] = "Requested",
    [2] = "In Progress",
    [3] = "Alternate Assigned",
    [4] = "Assigned",
    [5] = "Failed",
    [6] = "Unprocessed",
    [7] = "Invalid",
    [8] = "Released"
}
local resource_type = {
    [0] = "Reserved",
    [1] = "Continuous Feed Session",
    [2] = "Atm Connection",
    [3] = "MPEG Program",
    [4] = "Physical Channel",
    [5] = "TS Upstream Bandwidth",
    [6] = "TS Downstream Bandwidth",
    [7] = "Atm Svc Connection",
    [8] = "Connection Notify",
    [9] = "IP",
    [10] = "Client TDMA Assignment",
    [11] = "PSTN Setup",
    [12] = "NISDN Setup",
    [13] = "NISDN Connection",
    [14] = "Q.922 Connections",
    [15] = "Headend List",
    [16] = "Atm Vc Connection",
    [17] = "SDB Continuous Feed",
    [18] = "SDB Associations",
    [19] = "SDB Entitlement",
    [32766] = "Shared Resource",
    [32767] = "Shared Request ID",
    [61441] = "Modulation Mode",
    [61443] = "Headend ID",
    [61444] = "Server Conditional Access",
    [61445] = "Client Conditional Access",
    [61446] = "Ethernet Interface",
    [61447] = "Service Group",
    [65535] = "Type Owner"
}
local transid_originator = {
    [0] = "Assigned by Client",
    [1] = "Assigned by Server",
    [2] = "Assigned by Network",
    [3] = "Reserved"
}
local resource_assignor = {
    [0] = "Reserved",
    [1] = "Client",
    [2] = "Server",
    [3] = "Network"
}
local resource_allocator = {
    [0] = "Unspecified",
    [1] = "Client",
    [2] = "Server",
    [3] = "Network"
}
local resource_attribute = {
    [0] = "Mandatory Non-Negotiable",
    [1] = "Mandatory Negotiable",
    [2] = "Non-Mandatory Non-Negotiable",
    [3] = "Non-Mandatory Negotiable",
    [4] = "Reserved",
    [5] = "Reserved",
    [6] = "Reserved",
    [7] = "Reserved",
    [8] = "Reserved",
    [9] = "Reserved",
    [10] = "Reserved",
    [11] = "Reserved",
    [12] = "Reserved",
    [13] = "Reserved",
    [14] = "Reserved",
    [15] = "Reserved"
}
local resource_view = {
    [0] = "Reserved",
    [1] = "Client View",
    [2] = "Server View",
    [3] = "Reserved"
}
local headend_flag = {
    [0] = "Reserved",
    [1] = "Session is intended for the Headend named by HeadendID",
    [2] = "Session is intended for the Headend where the content was introduced into the network",
    [3] = "Session is intended for all Headends that have QAMs",
    [4] = "Session is intended for the QAM with an output TSID named by the TSID field"
}
local casystemid = {
    [2411] = "VGS",
    [3584] = "PowerKey"
}

-- creates a Proto object, but doesn't register it yet
local twcssp = Proto("dsmcc_ssp_udp","Pegasus Session Setup Protocol (Client-Side)")


----------------------------------------
-- Proto Fields
ssp_fields = {}
-- dsmcc header
ssp_fields.pf_protocol_descriminator = ProtoField.uint8("dsmcc_ssp_udp.protocol_descriminator", "Protocol Descriminator", base.HEX, discriminator)
ssp_fields.pf_dsmcc_type             = ProtoField.uint8("dsmcc_ssp_udp.dsmcc_type", "DSMCC Type", base.HEX, dsmcc_types)
ssp_fields.pf_message_id             = ProtoField.uint16("dsmcc_ssp_udp.message_id", "Message ID", base.HEX, message_types)
ssp_fields.pf_message_discriminator  = ProtoField.uint16("dsmcc_ssp_udp.message_discriminator", "Discriminator", base.HEX, message_discriminator, 0xC000)
ssp_fields.pf_message_scenario       = ProtoField.uint16("dsmcc_ssp_udp.message_scenario", "Scenario", base.HEX, message_scenario, 0x3FF0)
ssp_fields.pf_message_type           = ProtoField.uint16("dsmcc_ssp_udp.message_type", "Type", base.HEX, message_type, 0x000F)
ssp_fields.pf_transaction_id         = ProtoField.new("Transaction ID", "dsmcc_ssp_udp.transaction_id", ftypes.UINT32)
ssp_fields.pf_flag_transactionid_originator = ProtoField.uint32("dsmcc_ssp_udp.flag_transactionid_originator", "Originator", base.DEC, transid_originator, 0xC0000000)
ssp_fields.pf_flag_transactionid_number     = ProtoField.new("Value", "dsmcc_ssp_udp.flag_transactionid_number", ftypes.UINT32, nil, base.DEC, 0x3FFFFFFF)
ssp_fields.pf_reserved               = ProtoField.new("Reserved", "dsmcc_ssp_udp.reserved", ftypes.BYTES)
ssp_fields.pf_adaptation_length      = ProtoField.new("Adaptation Length", "dsmcc_ssp_udp.adaptation_length", ftypes.UINT8)
ssp_fields.pf_adaptation_type        = ProtoField.uint8("dsmcc_ssp_udp.adaptation_type", "Adaptation Type", base.HEX, adaptation_type)
ssp_fields.pf_adaptation_data        = ProtoField.new("Adaptation Data", "dsmcc_ssp_udp.adaptation_data", ftypes.BYTES)
ssp_fields.pf_adaptation_ca_length   = ProtoField.new("Adaptation CA Length", "dsmcc_ssp_udp.adaptation_ca_length", ftypes.UINT16)
ssp_fields.pf_adaptation_ca_systemid = ProtoField.uint16("dsmcc_ssp_udp.adaptation_ca_systemid", "Adaptation CA System ID", base.DEC, casystemid)
ssp_fields.pf_adaptation_ca_data     = ProtoField.new("Adaptation CA Data", "dsmcc_ssp_udp.adaptation_ca_data", ftypes.BYTES)
ssp_fields.pf_adaptation_nsap_afi    = ProtoField.new("User NSAP (AFI)", "dsmcc_ssp_udp.adaptation_nsap_afi", ftypes.BYTES)
ssp_fields.pf_adaptation_icd         = ProtoField.new("International Code Designator (ICD)", "dsmcc_ssp_udp.adaptation_icd", ftypes.BYTES)
ssp_fields.pf_adaptation_ip          = ProtoField.new("User IP (HO_DSP)", "dsmcc_ssp_udp.adaptation_ip", ftypes.IPv4)
ssp_fields.pf_adaptation_mac         = ProtoField.new("User MAC (ESI)", "dsmcc_ssp_udp.adaptation_mac", ftypes.ETHER)
ssp_fields.pf_adaptation_sel         = ProtoField.new("NSAP Selector (SEL)", "dsmcc_ssp_udp.adaptation_sel", ftypes.BYTES)
ssp_fields.pf_message_length         = ProtoField.new("Message Length Payload", "dsmcc_ssp_udp.message_length", ftypes.UINT16)
-- session count
ssp_fields.pf_session_count          = ProtoField.new("Session Count","dsmcc_ssp_udp.session_count", ftypes.UINT16)
-- session id
ssp_fields.pf_stb_address            = ProtoField.new("STB MAC Address", "dsmcc_ssp_udp.stb_address", ftypes.ETHER)
ssp_fields.pf_session_number         = ProtoField.new("Session Number", "dsmcc_ssp_udp.session_number", ftypes.UINT32)
-- return codes
ssp_fields.pf_response               = ProtoField.uint16("dsmcc_ssp_udp.response", "Response Code", base.HEX, response_codes)
ssp_fields.pf_reason                 = ProtoField.uint16("dsmcc_ssp_udp.reason", "Reason Code", base.HEX, reason_codes)
-- client nsap, E.164 ATM
ssp_fields.pf_client_nsap_afi        = ProtoField.new("Client NSAP (AFI)", "dsmcc_ssp_udp.client_nsap_api", ftypes.BYTES)
ssp_fields.pf_client_icd             = ProtoField.new("International Code Designator (ICD)", "dsmcc_ssp_udp.client_icd", ftypes.BYTES)
ssp_fields.pf_client_ip              = ProtoField.new("Client IP (HO_DSP)", "dsmcc_ssp_udp.client_ip", ftypes.IPv4)
ssp_fields.pf_client_mac             = ProtoField.new("Client MAC (ESI)", "dsmcc_ssp_udp.client_mac", ftypes.ETHER)
ssp_fields.pf_client_sel             = ProtoField.new("NSAP Selector (SEL)", "dsmcc_ssp_udp.client_sel", ftypes.BYTES)
-- server nsap, E.164 ATM
ssp_fields.pf_server_nsap_afi        = ProtoField.new("Server NSAP (AFI)", "dsmcc_ssp_udp.server_nsap_api", ftypes.BYTES)
ssp_fields.pf_server_icd             = ProtoField.new("International Code Designator (ICD)", "dsmcc_ssp_udp.server_icd", ftypes.BYTES)
ssp_fields.pf_server_ip              = ProtoField.new("Server IP (HO_DSP)", "dsmcc_ssp_udp.server_ip", ftypes.IPv4)
ssp_fields.pf_server_mac             = ProtoField.new("Server MAC (ESI)", "dsmcc_ssp_udp.server_mac", ftypes.ETHER)
ssp_fields.pf_server_sel             = ProtoField.new("NSAP Selector (SEL)", "dsmcc_ssp_udp.server_sel", ftypes.BYTES)
-- user data
ssp_fields.pf_uudata_length          = ProtoField.new("UUData Length", "dsmcc_ssp_udp.uudata_length", ftypes.UINT16)
ssp_fields.pf_private_data_length    = ProtoField.new("Private Data Length", "dsmcc_ssp_udp.private_data_length", ftypes.UINT16)
ssp_fields.pf_protocol_id            = ProtoField.new("Protocol ID", "dsmcc_ssp_udp.protocol_id", ftypes.BYTES)
ssp_fields.pf_version                = ProtoField.new("Protocol Version", "dsmcc_ssp_udp.version", ftypes.BYTES)
ssp_fields.pf_descriptor_count       = ProtoField.new("Descriptor Count", "dsmcc_ssp_udp.descriptor_count", ftypes.UINT8)
-- descriptor 01 asset id
ssp_fields.pf_desc_asset_id_tag              = ProtoField.new("Asset ID Tag", "dsmcc_ssp_udp.desc_asset_id_tag", ftypes.UINT8)
ssp_fields.pf_desc_asset_id_length           = ProtoField.new("Asset ID Length", "dsmcc_ssp_udp.desc_asset_id_length", ftypes.UINT8)
ssp_fields.pf_desc_collection_id_data        = ProtoField.new("Collection ID", "dsmcc_ssp_udp.desc_collection_id_data", ftypes.UINT32)
ssp_fields.pf_desc_asset_id_data             = ProtoField.new("Asset ID", "dsmcc_ssp_udp.desc_asset_id_data", ftypes.UINT32)
-- descriptor 02 nodegroup id
ssp_fields.pf_desc_nodegroup_id_tag          = ProtoField.new("Node Group ID Tag", "dsmcc_ssp_udp.desc_nodegroup_id_tag", ftypes.UINT8)
ssp_fields.pf_desc_nodegroup_id_length       = ProtoField.new("Node Group ID Length", "dsmcc_ssp_udp.desc_nodegroup_id_length", ftypes.UINT8)
ssp_fields.pf_desc_nodegroup_id_data         = ProtoField.new("Node Group ID", "dsmcc_ssp_udp.desc_nodegroup_id_data", ftypes.BYTES)
-- descriptor 03 ip
ssp_fields.pf_desc_ip_tag                    = ProtoField.new("IP Tag", "dsmcc_ssp_udp.desc_ip_tag", ftypes.UINT8)
ssp_fields.pf_desc_ip_length                 = ProtoField.new("IP Length", "dsmcc_ssp_udp.desc_ip_length", ftypes.UINT8)
ssp_fields.pf_desc_ip_data_port              = ProtoField.new("IP Port", "dsmcc_ssp_udp.desc_ip_data_port", ftypes.UINT16)
ssp_fields.pf_desc_ip_data                   = ProtoField.new("IP Address", "dsmcc_ssp_udp.desc_ip_data", ftypes.IPv4)
-- descriptor 04 stream handle
ssp_fields.pf_desc_stream_handle_tag         = ProtoField.new("Stream Handle Tag", "dsmcc_ssp_udp.desc_stream_handle_tag", ftypes.UINT8)
ssp_fields.pf_desc_stream_handle_length      = ProtoField.new("Stream Handle Length", "dsmcc_ssp_udp.desc_stream_handle_length", ftypes.UINT8)
ssp_fields.pf_desc_stream_handle_data        = ProtoField.new("Stream Handle", "dsmcc_ssp_udp.desc_stream_handle_data", ftypes.UINT32)
-- descriptor 05 application request
ssp_fields.pf_desc_app_request_tag           = ProtoField.new("Application Request Tag", "dsmcc_ssp_udp.desc_app_request_tag", ftypes.UINT8)
ssp_fields.pf_desc_app_request_length        = ProtoField.new("Application Request Length", "dsmcc_ssp_udp.desc_app_request_length", ftypes.UINT8)
ssp_fields.pf_desc_app_request_data          = ProtoField.new("Application Request", "dsmcc_ssp_udp.desc_app_request_data", ftypes.STRING)
ssp_fields.pf_desc_app_request_purchase_type = ProtoField.uint8("dsmcc_ssp_udp.desc_app_request_purchase_type", "Purchase Type", base.HEX, purchase_type_request)
ssp_fields.pf_desc_app_request_rental_list_start = ProtoField.new("Rental List Request Start", "dsmcc_ssp_udp.desc_app_request_rental_list_start", ftypes.UINT8)
ssp_fields.pf_desc_app_request_rental_list_count = ProtoField.new("Rental List Request Count", "dsmcc_ssp_udp.desc_app_request_rental_list_count", ftypes.UINT8)
ssp_fields.pf_desc_app_request_service_name      = ProtoField.new("Service Name", "dsmcc_ssp_udp.desc_app_request_service_name", ftypes.STRING)
-- descriptor 06 application response
ssp_fields.pf_desc_app_response_tag           = ProtoField.new("Application Response Tag", "dsmcc_ssp_udp.desc_app_response_tag", ftypes.UINT8)
ssp_fields.pf_desc_app_response_length        = ProtoField.new("Application Response Length", "dsmcc_ssp_udp.desc_app_response_length", ftypes.UINT8)
ssp_fields.pf_desc_app_response_data          = ProtoField.new("Application Response", "dsmcc_ssp_udp.desc_app_response_data", ftypes.STRING)
ssp_fields.pf_desc_app_response_purchase_type = ProtoField.uint8("dsmcc_ssp_udp.desc_app_response_purchase_type", "Purchase Type", base.HEX, purchase_type_response)
ssp_fields.pf_desc_app_response_failure_code  = ProtoField.uint8("dsmcc_ssp_udp.desc_app_response_failure", "Response Failure", base.HEX, response_failure_code)
ssp_fields.pf_desc_app_response_purchase_id   = ProtoField.new("Purchase ID", "dsmcc_ssp_udp.desc_app_response_purchase_id", ftypes.UINT32)
ssp_fields.pf_desc_app_response_offering_id   = ProtoField.new("Offering ID", "dsmcc_ssp_udp.desc_app_response_offering_id", ftypes.UINT32)
ssp_fields.pf_desc_app_response_num_subs      = ProtoField.new("Number of Subscriptions", "dsmcc_ssp_udp.desc_app_response_num_subs", ftypes.UINT8)
ssp_fields.pf_desc_app_response_sub_expiry    = ProtoField.new("Subscription Expiration", "dsmcc_ssp_udp.desc_app_response_sub_expiry", ftypes.ABSOLUTE_TIME)
-- descriptor 17 folder id
ssp_fields.pf_desc_folderid_tag           = ProtoField.new("Folder ID Tag", "dsmcc_ssp_udp.desc_app_folderid_tag", ftypes.UINT8)
ssp_fields.pf_desc_folderid_length        = ProtoField.new("Folder ID Length", "dsmcc_ssp_udp.desc_app_folderid_length", ftypes.UINT8)
ssp_fields.pf_desc_folderid_data          = ProtoField.new("Folder ID", "dsmcc_ssp_udp.desc_app_folderid_data", ftypes.BYTES)
-- descriptor 240 transport stream id
ssp_fields.pf_desc_tsid_tag               = ProtoField.new("Transport Stream ID Tag", "dsmcc_ssp_udp.desc_tsid_tag", ftypes.BYTES)
ssp_fields.pf_desc_tsid_length            = ProtoField.new("Transport Stream ID Length", "dsmcc_ssp_udp.desc_tsid_length", ftypes.UINT8)
ssp_fields.pf_desc_tsid_data              = ProtoField.new("Transport Stream ID", "dsmcc_ssp_udp.desc_tsid_data", ftypes.UINT16)
-- resource descriptors
ssp_fields.pf_resource_count              = ProtoField.new("Resource Count", "dsmcc_ssp_udp.resource_count", ftypes.UINT16)
-- resource descriptor headers
ssp_fields.pf_resource_request_id         = ProtoField.new("Resource Request ID","dsmcc_ssp_udp.resource_request_id", ftypes.BYTES)
ssp_fields.pf_resource_desc_type          = ProtoField.uint16("dsmcc_ssp_udp.resource_desc_type", "Resource Descriptor Type", base.DEC, resource_type)
ssp_fields.pf_resource_num                = ProtoField.new("Resource Number", "dsmcc_ssp_udp.resource_num", ftypes.BYTES)
ssp_fields.pf_flag_resource_num_assignor  = ProtoField.uint16("dsmcc_ssp_udp.flag_resource_num_assignor", "Assignor", base.DEC, resource_assignor, 0xC000)
ssp_fields.pf_flag_resource_num_value     = ProtoField.new("Value", "dsmcc_ssp_udp.flag_resource_num_value", ftypes.UINT16, nil, base.HEX, 0x3FFF)
ssp_fields.pf_resource_association_tag    = ProtoField.new("Resource Association Tag", "dsmcc_ssp_udp.resource_association_tag", ftypes.BYTES)
ssp_fields.pf_flag_resource_association_tag_assignor = ProtoField.uint16("dsmcc_ssp_udp.flag_resource_association_tag_assignor", "Assignor", base.DEC, resource_assignor, 0xC000)
ssp_fields.pf_flag_resource_association_tag_value    = ProtoField.new("Value", "dsmcc_ssp_udp.flag_resource_association_tag_value", ftypes.UINT16, nil, base.HEX, 0x3FFF)
ssp_fields.pf_resource_flags              = ProtoField.new("Resource Flags", "dsmcc_ssp_udp.resource_flags", ftypes.BYTES)
ssp_fields.pf_resource_flags_view         = ProtoField.uint8("dsmcc_ssp_udp.resource_flags_view", "View", base.HEX, resource_view, 0xC0)
ssp_fields.pf_resource_flags_attribute    = ProtoField.uint8("dsmcc_ssp_udp.resource_flags_attribute", "Attribute", base.HEX, resource_attribute, 0x3C)
ssp_fields.pf_resource_flags_allocator    = ProtoField.uint8("dsmcc_ssp_udp.resource_flags_allocator", "Allocator", base.HEX, resource_allocator, 0x03)
ssp_fields.pf_resource_status             = ProtoField.uint8("dsmcc_ssp_udp.resource_status", "Resource Status", base.HEX, resource_status)
ssp_fields.pf_resource_length             = ProtoField.new("Resource Length", "dsmcc_ssp_udp.resource_length", ftypes.UINT16)
ssp_fields.pf_resource_data_field_count   = ProtoField.new("Resource Data Field Count", "dsmcc_ssp_udp.resource_data_field_count", ftypes.UINT16)
-- resource descriptor 0003 mpeg program
ssp_fields.pf_resource_value_type         = ProtoField.uint16("dsmcc_ssp_udp.resource_value_type", "Resource Value Type", base.HEX, res_value_type)
ssp_fields.pf_resource_value_count        = ProtoField.new("Resource Value Count", "dsmcc_ssp_udp.resource_value_count", ftypes.UINT16)
ssp_fields.pf_resource_mpeg_program_num   = ProtoField.new("MPEG Program Number", "dsmcc_ssp_udp.resource_mpeg_program_num", ftypes.BYTES)
ssp_fields.pf_resource_mpeg_pmt_pid       = ProtoField.new("MPEG PMT PID", "dsmcc_ssp_udp.resource_mpeg_pmt_pid", ftypes.BYTES)
ssp_fields.pf_resource_mpeg_ca_pid        = ProtoField.new("MPEG CA PID", "dsmcc_ssp_udp.resource_mpeg_ca_pid", ftypes.BYTES)
ssp_fields.pf_resource_mpeg_stream_count  = ProtoField.new("Elementary Stream Count", "dsmcc_ssp_udp.resource_mpeg_stream_count", ftypes.UINT16)
ssp_fields.pf_resource_mpeg_pid           = ProtoField.new("MPEG PID", "dsmcc_ssp_udp.resource_mpeg_pcr", ftypes.BYTES)
ssp_fields.pf_resource_mpeg_stream_type   = ProtoField.new("Stream Type", "dsmcc_ssp_udp.resource_mpeg_stream_type", ftypes.BYTES)
ssp_fields.pf_resource_mpeg_association_tag = ProtoField.new("Association Tag", "dsmcc_ssp_udp.resource_mpeg_association_tag", ftypes.BYTES)
ssp_fields.pf_resource_mpeg_pcr           = ProtoField.new("MPEG PCR", "dsmcc_ssp_udp.resource_mpeg_pcr", ftypes.BYTES)
-- resource descriptor 0004 physical channel
ssp_fields.pf_resource_channel_id         = ProtoField.new("Channel ID (Hz)", "dsmcc_ssp_udp.resource_channel_id", ftypes.UINT32)
ssp_fields.pf_resource_direction          = ProtoField.uint16("dsmcc_ssp_udp.resource_direction", "Direction", base.HEX, physical_direction)
-- resource descriptor 0006 ts downstream bandwidth
ssp_fields.pf_resource_ds_bw              = ProtoField.new("Downstream Bandwidth (bps)", "dsmcc_ssp_udp.resource_ds_bw", ftypes.UINT16)
ssp_fields.pf_resource_value              = ProtoField.new("Resource Value", "dsmcc_ssp_udp.resource_value", ftypes.BYTES)
ssp_fields.pf_resource_ds_tsid            = ProtoField.new("Downstream Transport Stream ID", "dsmcc_ssp_udp.resource_ds_tsid", ftypes.UINT16)
-- resource descriptor F001 atsc modulation mode
ssp_fields.pf_resource_trans_system       = ProtoField.uint8("dsmcc_ssp_udp.resource_trans_system", "Transmission System", base.HEX, transmission_systems)
ssp_fields.pf_resource_inner_coding       = ProtoField.new("Inner Coding Mode", "dsmcc_ssp_udp.resource_inner_coding", ftypes.BYTES)
ssp_fields.pf_resource_split_bitsream     = ProtoField.new("Split Bitstream Mode", "dsmcc_ssp_udp.resource_split_bitsream", ftypes.BYTES)
ssp_fields.pf_resource_mod_format         = ProtoField.uint8("dsmcc_ssp_udp.resource_mod_format", "Modulation Format", base.HEX, mod_format)
ssp_fields.pf_resource_symbol_rate        = ProtoField.new("Symbol Rate", "dsmcc_ssp_udp.resource_symbol_rate", ftypes.UINT32)
ssp_fields.pf_resource_reserved           = ProtoField.new("Reserved", "dsmcc_ssp_udp.resource_reserved", ftypes.BYTES)
ssp_fields.pf_resource_interleave_depth   = ProtoField.new("Interleave Depth", "dsmcc_ssp_udp.resource_interleave_depth", ftypes.BYTES)
ssp_fields.pf_resource_modulation_mode    = ProtoField.new("Modulation Mode", "dsmcc_ssp_udp.resource_modulation_mode", ftypes.BYTES)
ssp_fields.pf_resource_fec                = ProtoField.uint8("dsmcc_ssp_udp.resource_fec", "Forward Error Correction", base.HEX, fec)
-- resource descriptor F003 headend id
ssp_fields.pf_resource_headend_flag       = ProtoField.uint16("dsmcc_ssp_udp.resource_headend_flag", "Headend Flag", base.HEX, headend_flag)
ssp_fields.pf_resource_headend_afi        = ProtoField.new("Headend NSAP (AFI)", "dsmcc_ssp_udp.resource_server_ca_user_afi", ftypes.BYTES)
ssp_fields.pf_resource_headend_icd        = ProtoField.new("International Code Designator (ICD)", "dsmcc_ssp_udp.resource_server_ca_user_icd", ftypes.BYTES)
ssp_fields.pf_resource_headend_ip         = ProtoField.new("Headend IP (HO_DSP)", "dsmcc_ssp_udp.resource_server_ca_user_ip", ftypes.IPv4)
ssp_fields.pf_resource_headend_mac        = ProtoField.new("Headend MAC (ESI)", "dsmcc_ssp_udp.resource_server_ca_user_mac", ftypes.ETHER)
ssp_fields.pf_resource_headend_sel        = ProtoField.new("NSAP Selector (SEL)", "dsmcc_ssp_udp.resource_server_ca_user_sel", ftypes.BYTES)
ssp_fields.pf_resource_headend_tsid       = ProtoField.new("Headend TSID", "dsmcc_ssp_udp.resource_headend_tsid", ftypes.BYTES)
-- resource descriptor F004 server conditional access
ssp_fields.pf_resource_server_ca_system_id   = ProtoField.new("Server CA System ID", "dsmcc_ssp_udp.resource_server_ca_system_id", ftypes.BYTES)
ssp_fields.pf_resource_server_ca_copyprotect = ProtoField.new("Server CA Copy Protection", "dsmcc_ssp_udp.resource_server_ca_copyprotect", ftypes.BYTES)
ssp_fields.pf_resource_server_ca_usercount   = ProtoField.new("Server CA User Count", "dsmcc_ssp_udp.resource_server_ca_usercount", ftypes.UINT16)
ssp_fields.pf_resource_server_ca_userid      = ProtoField.new("Server CA User ID", "dsmcc_ssp_udp.resource_server_ca_userid", ftypes.BYTES)
ssp_fields.pf_resource_server_ca_user_afi    = ProtoField.new("User NSAP (AFI)", "dsmcc_ssp_udp.resource_server_ca_user_afi", ftypes.BYTES)
ssp_fields.pf_resource_server_ca_user_icd    = ProtoField.new("International Code Designator (ICD)", "dsmcc_ssp_udp.resource_server_ca_user_icd", ftypes.BYTES)
ssp_fields.pf_resource_server_ca_user_ip     = ProtoField.new("Server CA User IP (HO_DSP)", "dsmcc_ssp_udp.resource_server_ca_user_ip", ftypes.IPv4)
ssp_fields.pf_resource_server_ca_user_mac    = ProtoField.new("Server CA User MAC (ESI)", "dsmcc_ssp_udp.resource_server_ca_user_mac", ftypes.ETHER)
ssp_fields.pf_resource_server_ca_user_sel    = ProtoField.new("NSAP Selector (SEL)", "dsmcc_ssp_udp.resource_server_ca_user_sel", ftypes.BYTES)
-- resource descriptor F005 client conditional access
ssp_fields.pf_resource_client_ca_system_id   = ProtoField.new("CA System ID", "dsmcc_ssp_udp.resource_ca_system_id", ftypes.BYTES)
ssp_fields.pf_resource_client_ca_info_length = ProtoField.new("CA Info Length", "dsmcc_ssp_udp.resource_ca_info_length", ftypes.UINT16)
ssp_fields.pf_resource_client_ca_info_data   = ProtoField.new("CA Info Data", "dsmcc_ssp_udp.resource_ca_info_data", ftypes.BYTES)
-- resource descriptor F006 ethernet interface
ssp_fields.pf_resource_ethernet_src_udp = ProtoField.new("Ethernet Src UDP", "dsmcc_ssp_udp.resource_ethernet_src_udp", ftypes.UINT16)
ssp_fields.pf_resource_ethernet_src_ip  = ProtoField.new("Ethernet Src IP", "dsmcc_ssp_udp.resource_ethernet_src_ip", ftypes.IPv4)
ssp_fields.pf_resource_ethernet_src_mac = ProtoField.new("Ethernet Src Mac", "dsmcc_ssp_udp.resource_ethernet_src_mac", ftypes.ETHER)
ssp_fields.pf_resource_ethernet_dst_udp = ProtoField.new("Ethernet Dst UDP", "dsmcc_ssp_udp.resource_ethernet_dst_udp", ftypes.UINT16)
ssp_fields.pf_resource_ethernet_dst_ip  = ProtoField.new("Ethernet Src IP", "dsmcc_ssp_udp.resource_ethernet_dst_ip", ftypes.IPv4)
ssp_fields.pf_resource_ethernet_dst_mac = ProtoField.new("Ethernet Dst Mac", "dsmcc_ssp_udp.resource_ethernet_dst_mac", ftypes.ETHER)
-- resource descriptor F007 service group
ssp_fields.pf_resource_service_group    = ProtoField.new("Service Group", "dsmcc_ssp_udp.resource_service_group", ftypes.UINT32)
-- service gateway
ssp_fields.pf_sg                        = ProtoField.new("Service Gateway", "dsmcc_ssp_udp.sg", ftypes.STRING)
ssp_fields.pf_sg_data_length            = ProtoField.new("Service Gateway Data Length", "dsmcc_ssp_udp.sg_data_length", ftypes.UINT32)
ssp_fields.pf_sg_service                = ProtoField.new("Service Gateway Service", "dsmcc_ssp_udp.sg_service", ftypes.STRING)
ssp_fields.pf_sg_service_data_length    = ProtoField.new("Service Gateway Service Data Length", "dsmcc_ssp_udp.sg_service_data_length", ftypes.UINT32)
-- debug, change the ftype based on the actual data type being discovered
ssp_fields.pf_debug   = ProtoField.new("Debug", "dsmcc_ssp_udp.debug", ftypes.BYTES)
ssp_fields.pf_unknown = ProtoField.new("Unknown or Padding", "dsmcc_ssp_udp.unknown", ftypes.BYTES)

----------------------------------------
-- this registers the ProtoFields above into the protocol
twcssp.fields = ssp_fields

----------------------------------------
-- create some expert info fields (this is new functionality in 1.11.3)
--local ef_query     = ProtoExpert.new("dsmcc_ssp_udp.query.expert", "SSP query message", expert.group.REQUEST_CODE, expert.severity.CHAT)
--local ef_response  = ProtoExpert.new("dsmcc_ssp_udp.response.expert", "SSP response message", expert.group.RESPONSE_CODE, expert.severity.CHAT)
local ef_too_short = ProtoExpert.new("dsmcc_ssp_udp.too_short.expert", "SSP message too short", expert.group.MALFORMED, expert.severity.ERROR)
local ef_bad_descriptor = ProtoExpert.new("dsmcc_ssp_udp.descriptor.missing.expert", "SSP descriptor missing or malformed", expert.group.MALFORMED, expert.severity.WARN)

-- register them
--twcssp.experts = { ef_query, ef_too_short, ef_too_long, ef_bad_descriptor, ef_response }
twcssp.experts = { ef_too_short, ef_bad_descriptor }
----------------------------------------

--------------------------
-- Preferences handling --
--------------------------
local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}
twcssp.prefs.debug = Pref.enum("Debug", default_settings.debug_level, "The debug printing level", debug_pref_enum)
twcssp.prefs.port  = Pref.uint("Port number", default_settings.port, "The UDP port number for DSMCC SSP")
twcssp.prefs.heur  = Pref.bool("Heuristic enabled", default_settings.heur_enabled, "Whether heuristic dissection is enabled or not")

----------------------------------------
-- a function for handling prefs being changed
function twcssp.prefs_changed()
    dprint2("prefs_changed called")
    default_settings.debug_level = twcssp.prefs.debug
    reset_debug_level()
    default_settings.heur_enabled = twcssp.prefs.heur
    if default_settings.port ~= twcssp.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            dprint2("removing SSP from port",default_settings.port)
            DissectorTable.get("udp.port"):remove(default_settings.port, twcssp)
        end
        -- set our new default
        default_settings.port = twcssp.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            dprint2("adding SSP to port",default_settings.port)
            DissectorTable.get("udp.port"):add(default_settings.port, twcssp)
        end
    end
end
dprint2("SSP preferences registered")


----------------------------------------

--          START DISSECTION          --

----------------------------------------

-- the DSMCC header size
local SSP_HDR_LEN = 12

-- the smallest possible SSP field sizes
-- depends on messageid
local MIN_DESC_LEN = 3   -- tag, length, one data byte
local MIN_RSRC_LEN = 16  -- header, one data byte

----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "dsmcc_ssp_udp.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that the Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.

function twcssp.dissector(tvbuf,pktinfo,root)
    dprint2("dsmcc_ssp_udp.dissector called")
    
    -- set the protocol column to show the protocol name
    pktinfo.cols.protocol:set("DSMCC_SSP_UDP")
    
    -- Check that the packet size is rational during dissection, get the length of the packet buffer (Tvb).
    -- Use tvb:len() or tvb:reported_len() here; but tvb:reported_length_remaining() is preferred because it's safer.
    local pktlen = tvbuf:reported_length_remaining()

    -- Check header is not too short
    if pktlen < SSP_HDR_LEN then
        tree:add_proto_expert_info(ef_too_short)
        dprint("packet length",pktlen,"too short")
        return
    end
        
    -- Add the protocol to the dissection display tree.
    local tree = root:add(twcssp, tvbuf:range(0,pktlen))
    
    local folder_tree = tree:add("DSM-CC Header")
    folder_tree:add(ssp_fields.pf_protocol_descriminator, tvbuf:range(0,1))
    folder_tree:add(ssp_fields.pf_dsmcc_type, tvbuf:range(1,1))
    msg_tree = folder_tree:add(ssp_fields.pf_message_id, tvbuf:range(2,2))
    msg_tree:add(ssp_fields.pf_message_discriminator, tvbuf:range(2,2))
    msg_tree:add(ssp_fields.pf_message_scenario, tvbuf:range(2,2))
    msg_tree:add(ssp_fields.pf_message_type, tvbuf:range(2,2))
    local trans_tree = folder_tree:add(ssp_fields.pf_transaction_id, tvbuf:range(4,4))
    trans_tree:add(ssp_fields.pf_flag_transactionid_originator, tvbuf:range(4,4))
    trans_tree:add(ssp_fields.pf_flag_transactionid_number, tvbuf:range(4,4))
    folder_tree:add(ssp_fields.pf_reserved, tvbuf:range(8,1))
    folder_tree:add(ssp_fields.pf_adaptation_length, tvbuf:range(9,1))
    local adaptation_length = tvbuf:range(9,1):uint()
    folder_tree:add(ssp_fields.pf_message_length, tvbuf:range(10,2))
    pos = 12
    if adaptation_length > 0 then
        adapt_tree = folder_tree:add(ssp_fields.pf_adaptation_type, tvbuf:range(pos,1))
        local atype = tvbuf:range(pos,1):uint()
        pos = pos + 1
        if atype == 1 then  -- ca system id
            adapt_tree:add(ssp_fields.pf_reserved, tvbuf:range(pos,1))
            pos = pos + 1
            adapt_tree:add(ssp_fields.pf_adaptation_ca_systemid, tvbuf:range(pos,2))
            pos = pos + 2
            adapt_tree:add(ssp_fields.pf_adaptation_ca_length, tvbuf:range(pos,2))
            local ca_length = tvbuf:range(pos,2):uint()
            pos = pos + 2
            if ca_length > 0 then
                adapt_tree:add(ssp_fields.pf_adaptation_ca_data, tvbuf:range(pos,ca_length))
                pos = pos + ca_length
            end
        elseif atype == 2 then  -- user id
            adapt_tree:add(ssp_fields.pf_reserved, tvbuf:range(pos,1))
            pos = pos + 1
            adapt_tree:add(ssp_fields.pf_adaptation_nsap_afi, tvbuf:range(pos,1))
            pos = pos + 1
            adapt_tree:add(ssp_fields.pf_adaptation_icd, tvbuf:range(pos,8))
            pos = pos + 8
            adapt_tree:add(ssp_fields.pf_adaptation_ip, tvbuf:range(pos,4))
            pos = pos + 4
            adapt_tree:add(ssp_fields.pf_adaptation_mac, tvbuf:range(pos,6))
            pos = pos + 6
            adapt_tree:add(ssp_fields.pf_adaptation_sel, tvbuf:range(pos,1))
            pos = pos + 1
        else -- reserved
            adapt_tree:add(ssp_fields.pf_adaptation_data, tvbuf:range(pos,adaptation_length-1))
            pos = pos + adaptation_length-1
        end
    end

    -- Get the current message id to parse each SSP message type accordingly
    local messageid = tvbuf:range(2,2):uint()

    ------------------------------------
    --  Client Session Setup Request  --
    ------------------------------------
    if messageid == 0x4010 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pktinfo.cols.info = "Client Session Setup Request (CSSR), mac="..mac .. ", session="..session
        pos = pos + 4
        local folder_tree = tree:add("Reserved")
        folder_tree:add(ssp_fields.pf_reserved, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("Client NSAP (E.164 ATM)")
        folder_tree:add(ssp_fields.pf_client_nsap_afi, tvbuf:range(pos,1))
        pos = pos + 1
        folder_tree:add(ssp_fields.pf_client_icd, tvbuf:range(pos,8))
        pos = pos + 8
        folder_tree:add(ssp_fields.pf_client_ip, tvbuf:range(pos,4))
        pos = pos + 4
        folder_tree:add(ssp_fields.pf_client_mac, tvbuf:range(pos,6))
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_client_sel, tvbuf:range(pos,1))
        pos = pos + 1
        local folder_tree = tree:add("Server NSAP (E.164 ATM)")
        folder_tree:add(ssp_fields.pf_server_nsap_afi, tvbuf:range(pos,1))
        pos = pos + 1
        folder_tree:add(ssp_fields.pf_server_icd, tvbuf:range(pos,8))
        pos = pos + 8
        folder_tree:add(ssp_fields.pf_server_ip, tvbuf:range(pos,4))
        pos = pos + 4
        folder_tree:add(ssp_fields.pf_server_mac, tvbuf:range(pos,6))
        pos = pos + 6        
        folder_tree:add(ssp_fields.pf_server_sel, tvbuf:range(pos,1))
        pos = pos + 1
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
        local protocol_id = tvbuf:range(pos,1):uint()
        pos = pos + 1
        folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
        pos = pos + 1
        -- render descriptors based on version 2 or 1 of SSP spec
        -- SSP version 2
        if (protocol_id == 2) then
            local folder_tree = tree:add("Service Gateway")
            folder_tree:add(ssp_fields.pf_sg, tvbuf:range(pos,16))
            pos = pos + 16
            folder_tree:add(ssp_fields.pf_sg_data_length, tvbuf:range(pos,4))
            pos = pos + 4
            folder_tree:add(ssp_fields.pf_sg_service, tvbuf:range(pos,16))
            pos = pos + 16
            folder_tree:add(ssp_fields.pf_sg_service_data_length, tvbuf:range(pos,4))
            pos = pos + 4
            -- service data (descriptors)
            local service_tree = folder_tree:add("Service Data")
            service_tree:add(ssp_fields.pf_descriptor_count, tvbuf:range(pos,1))
            local desc_count = tvbuf:range(pos,1):uint()
            pos = pos + 1
            for j=desc_count,1,-1 do
                local desc_tag = tvbuf:range(pos,1):uint()
                if (desc_tag == 1) then
                    local desc_tree = service_tree:add("Asset ID")
                    desc_tree:add(ssp_fields.pf_desc_asset_id_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_asset_id_length, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_asset_id_data, tvbuf:range(pos,4))
                    pos = pos + 4
                elseif (desc_tag == 2) then
                    local desc_tree = service_tree:add("Node Group ID")
                    desc_tree:add(ssp_fields.pf_desc_nodegroup_id_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_nodegroup_id_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_nodegroup_id_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                elseif (desc_tag == 3) then
                    local desc_tree = service_tree:add("IP")
                    desc_tree:add(ssp_fields.pf_desc_ip_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_ip_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    if desc_length > 4 then
                        desc_tree:add(ssp_fields.pf_desc_ip_data_port, tvbuf:range(pos,2))
                        pos = pos + 2
                        desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,4))
                        pos = pos + 4
                    else
                        desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    end
                elseif (desc_tag == 4) then
                    local desc_tree = service_tree:add("Stream Handle")
                    desc_tree:add(ssp_fields.pf_desc_stream_handle_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_stream_handle_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_stream_handle_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                elseif (desc_tag == 5) then
                    local desc_tree = service_tree:add("Application Request")
                    desc_tree:add(ssp_fields.pf_desc_app_request_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_app_request_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_app_request_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                elseif (desc_tag == 240) then
                    local desc_tree = service_tree:add("Transport Stream ID")
                    desc_tree:add(ssp_fields.pf_desc_tsid_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_tsid_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_tsid_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                else
                    tree:add("Unknown Descriptor, Check SSP spec!")
                    break
                end
            end
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        -- SSP version 1
        elseif (protocol_id == 1) then
            -- descriptors
            local folder_tree = tree:add("Descriptors")
            folder_tree:add(ssp_fields.pf_descriptor_count, tvbuf:range(pos,1))
            local desc_count = tvbuf:range(pos,1):uint()
            pos = pos + 1
            for i=desc_count,1,-1 do
                local desc_tag = tvbuf:range(pos,1):uint()
                if (desc_tag == 1) then
                    local desc_tree = folder_tree:add("Asset ID")
                    desc_tree:add(ssp_fields.pf_desc_asset_id_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_asset_id_length, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_collection_id_data, tvbuf:range(pos,4))
                    pos = pos + 4
                    desc_tree:add(ssp_fields.pf_desc_asset_id_data, tvbuf:range(pos,4))
                    pos = pos + 4
                elseif (desc_tag == 2) then
                    local desc_tree = folder_tree:add("Node Group ID")
                    desc_tree:add(ssp_fields.pf_desc_nodegroup_id_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_nodegroup_id_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_nodegroup_id_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                elseif (desc_tag == 3) then
                    local desc_tree = folder_tree:add("IP")
                    desc_tree:add(ssp_fields.pf_desc_ip_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_ip_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    if desc_length > 4 then
                        desc_tree:add(ssp_fields.pf_desc_ip_data_port, tvbuf:range(pos,2))
                        pos = pos + 2
                        desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,4))
                        pos = pos + 4
                    else
                        desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    end
                elseif (desc_tag == 4) then
                    local desc_tree = folder_tree:add("Stream Handle")
                    desc_tree:add(ssp_fields.pf_desc_stream_handle_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_stream_handle_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_stream_handle_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                elseif (desc_tag == 5) then
                    local desc_tree = folder_tree:add("Application Request")
                    desc_tree:add(ssp_fields.pf_desc_app_request_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_app_request_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_app_request_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                elseif (desc_tag == 240) then
                    local desc_tree = service_tree:add("Transport Stream ID")
                    desc_tree:add(ssp_fields.pf_desc_tsid_tag, tvbuf:range(pos,1))
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_tsid_length, tvbuf:range(pos,1))
                    local desc_length = tvbuf:range(pos,1):uint()
                    pos = pos + 1
                    desc_tree:add(ssp_fields.pf_desc_tsid_data, tvbuf:range(pos,desc_length))
                    pos = pos + desc_length
                else
                    tree:add("Unknown Descriptor, Check SSP spec!")
                    break
                end
            end
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        else
            tree:add("Unknown Protocol ID, Check SSP specs!")
        end
        
    ------------------------------------
    --  Client Session Setup Confirm  --
    ------------------------------------
    elseif messageid == 0x4011 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Session Setup Confirm (CSSC), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Response Code")
        folder_tree:add(ssp_fields.pf_response, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("Server NSAP (E.164 ATM)")
        folder_tree:add(ssp_fields.pf_server_nsap_afi, tvbuf:range(pos,1))
        pos = pos + 1
        folder_tree:add(ssp_fields.pf_server_icd, tvbuf:range(pos,8))
        pos = pos + 8
        folder_tree:add(ssp_fields.pf_server_ip, tvbuf:range(pos,4))
        pos = pos + 4
        folder_tree:add(ssp_fields.pf_server_mac, tvbuf:range(pos,6))
        pos = pos + 6        
        folder_tree:add(ssp_fields.pf_server_sel, tvbuf:range(pos,1))
        pos = pos + 1
        -- resources
        local folder_tree = tree:add("Resources")
        folder_tree:add(ssp_fields.pf_resource_count, tvbuf:range(pos,2))
        resource_count = tvbuf:range(pos,2):uint()
        pos = pos + 2
        res_count = 1
        if (resource_count > 0) then
            for i=resource_count,1,-1 do
                local resource_list = folder_tree:add("Resource",res_count)
                -- header
                local resource_tree = resource_list:add("Header")
                resource_tree:add(ssp_fields.pf_resource_request_id, tvbuf:range(pos,2))
                pos = pos + 2
                resource_tree:add(ssp_fields.pf_resource_desc_type, tvbuf:range(pos,2))
                local resource_type = tvbuf:range(pos,2):uint()
                pos = pos + 2
                -- MDMS supports 0003, 0004, 0006, F001
                if (resource_type == 3) or (resource_type == 4) or (resource_type == 6) or (resource_type == 61441) or (resource_type == 61443) or (resource_type == 61444) or (resource_type == 61445) or (resource_type == 61446) or (resource_type == 61447) then
                    local resource_num_tree = resource_tree:add(ssp_fields.pf_resource_num, tvbuf:range(pos,2))
                    resource_num_tree:add(ssp_fields.pf_flag_resource_num_assignor, tvbuf:range(pos,2))
                    resource_num_tree:add(ssp_fields.pf_flag_resource_num_value, tvbuf:range(pos,2))
                    pos = pos + 2
                    local resource_assoc_tree = resource_tree:add(ssp_fields.pf_resource_association_tag, tvbuf:range(pos,2))
                    resource_assoc_tree:add(ssp_fields.pf_flag_resource_association_tag_assignor, tvbuf:range(pos,2))
                    resource_assoc_tree:add(ssp_fields.pf_flag_resource_association_tag_value, tvbuf:range(pos,2))                    
                    pos = pos + 2
                    local resource_flags_tree = resource_tree:add(ssp_fields.pf_resource_flags, tvbuf:range(pos,1))
                    resource_flags_tree:add(ssp_fields.pf_resource_flags_view, tvbuf:range(pos,1))
                    resource_flags_tree:add(ssp_fields.pf_resource_flags_attribute, tvbuf:range(pos,1)) 
                    resource_flags_tree:add(ssp_fields.pf_resource_flags_allocator, tvbuf:range(pos,1)) 
                    pos = pos + 1
                    resource_tree:add(ssp_fields.pf_resource_status, tvbuf:range(pos,1))
                    pos = pos + 1
                    resource_tree:add(ssp_fields.pf_resource_length, tvbuf:range(pos,2))
                    resource_length = tvbuf:range(pos,2):uint()
                    pos = pos + 2
                    resource_tree:add(ssp_fields.pf_resource_data_field_count, tvbuf:range(pos,2))
                    pos = pos + 2
                    -- data
                    local resource_tree = resource_list:add("Data")
                    if (resource_type == 3) then  -- mpeg program
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_mpeg_program_num, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_mpeg_pmt_pid, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_mpeg_ca_pid, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_mpeg_stream_count, tvbuf:range(pos,2))
                        local elementary_stream_count = tvbuf:range(pos,2):uint()
                        pos = pos + 2
                        if elementary_stream_count > 0 then
                            local elementary_tree = resource_tree:add("MPEG Elementary Streams")
                            for j=elementary_stream_count,1,-1 do
                                elementary_tree:add(ssp_fields.pf_resource_mpeg_pid, tvbuf:range(pos,2))
                                pos = pos + 2
                                elementary_tree:add(ssp_fields.pf_resource_mpeg_stream_type, tvbuf:range(pos,1))
                                pos = pos + 1
                                elementary_tree:add(ssp_fields.pf_reserved, tvbuf:range(pos,1))
                                pos = pos + 1
                                elementary_tree:add(ssp_fields.pf_resource_mpeg_association_tag, tvbuf:range(pos,2))
                                pos = pos + 2
                            end
                        end
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_mpeg_pcr, tvbuf:range(pos,2))
                        pos = pos + 2
                    elseif (resource_type == 4) then  -- physical channel
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_channel_id, tvbuf:range(pos,4))
                        pos = pos + 4
                        resource_tree:add(ssp_fields.pf_resource_direction, tvbuf:range(pos,2))
                        pos = pos + 2
                    elseif (resource_type == 6) then  -- ts downstream bandwidth
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_ds_bw, tvbuf:range(pos,4))
                        pos = pos + 4
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_ds_tsid, tvbuf:range(pos,2))
                        pos = pos + 2
                    elseif (resource_type == 61441) then  -- atsc modulation mode
                        resource_tree:add(ssp_fields.pf_resource_trans_system, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_inner_coding, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_split_bitsream, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_mod_format, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_symbol_rate, tvbuf:range(pos,4))
                        pos = pos + 4
                        resource_tree:add(ssp_fields.pf_resource_reserved, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_interleave_depth, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_modulation_mode, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_fec, tvbuf:range(pos,1))
                        pos = pos + 1
--                    elseif (resource_type == 61442) then  -- reserved
                    elseif (resource_type == 61443) then  -- headend id
                        resource_tree:add(ssp_fields.pf_resource_headend_flag, tvbuf:range(pos,2))
                        pos = pos + 2
                        headend_tree = tree:add("Headend ID (NSAP)")
                        headend_tree:add(ssp_fields.pf_resource_headend_afi, tvbuf:range(pos,1))
                        pos = pos + 1
                        headend_tree:add(ssp_fields.pf_resource_headend_icd, tvbuf:range(pos,8))
                        pos = pos + 8
                        headend_tree:add(ssp_fields.pf_resource_headend_ip, tvbuf:range(pos,4))
                        pos = pos + 4
                        headend_tree:add(ssp_fields.pf_resource_headend_mac, tvbuf:range(pos,6))
                        pos = pos + 6
                        headend_tree:add(ssp_fields.pf_resource_headend_sel, tvbuf:range(pos,1))
                        pos = pos + 1
                        resource_tree:add(ssp_fields.pf_resource_headend_tsid, tvbuf:range(pos,4))
                        pos = pos + 4
                    elseif (resource_type == 61444) then  -- server conditional access
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_server_ca_system_id, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_server_ca_copyprotect, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_server_ca_usercount, tvbuf:range(pos,2))
                        usercount = tvbuf:range(pos,2):uint()
                        pos = pos + 2
                        if usercount > 0 then
                            resource_tree = tree:add("Users (NSAP)")
                            user = 1
                            for i=usercount,1,-1 do
                                user_list = resource_tree:add("User",user)
                                user_list:add(ssp_fields.pf_resource_server_ca_user_afi, tvbuf:range(pos,1))
                                pos = pos + 1
                                user_list:add(ssp_fields.pf_resource_server_ca_user_icd, tvbuf:range(pos,8))
                                pos = pos + 8
                                user_list:add(ssp_fields.pf_resource_server_ca_user_ip, tvbuf:range(pos,4))
                                pos = pos + 4
                                user_list:add(ssp_fields.pf_resource_server_ca_user_mac, tvbuf:range(pos,6))
                                pos = pos + 6
                                user_list:add(ssp_fields.pf_resource_server_ca_user_sel, tvbuf:range(pos,1))
                                pos = pos + 1
                                user = user + 1
                            end
                        end
                    elseif (resource_type == 61445) then  -- client conditional access
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_client_ca_system_id, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_client_ca_info_length, tvbuf:range(pos,2))
                        local cainfolength = tvbuf:range(pos,2):uint()
                        pos = pos + 2
                        if cainfolength > 0 then
                            resource_tree:add(ssp_fields.pf_resource_client_ca_info_data, tvbuf:range(pos,cainfolength))
                            pos = pos + cainfolength
                        end
                    elseif (resource_type == 61446) then  -- ethernet interface
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2                    
                        resource_tree:add(ssp_fields.pf_resource_value_count, tvbuf:range(pos,2))
                        pos = pos + 2   
                        resource_tree:add(ssp_fields.pf_resource_ethernet_src_udp, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_count, tvbuf:range(pos,2))
                        pos = pos + 2   
                        resource_tree:add(ssp_fields.pf_resource_ethernet_src_ip, tvbuf:range(pos,4))
                        pos = pos + 4
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_count, tvbuf:range(pos,2))
                        pos = pos + 2   
                        resource_tree:add(ssp_fields.pf_resource_ethernet_src_mac, tvbuf:range(pos,6))
                        pos = pos + 6
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_count, tvbuf:range(pos,2))
                        pos = pos + 2   
                        resource_tree:add(ssp_fields.pf_resource_ethernet_dst_udp, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_count, tvbuf:range(pos,2))
                        pos = pos + 2   
                        resource_tree:add(ssp_fields.pf_resource_ethernet_dst_ip, tvbuf:range(pos,4))
                        pos = pos + 4
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_value_count, tvbuf:range(pos,2))
                        pos = pos + 2   
                        resource_tree:add(ssp_fields.pf_resource_ethernet_dst_mac, tvbuf:range(pos,6))
                        pos = pos + 6
                    elseif (resource_type == 61447) then  -- service group
                        resource_tree:add(ssp_fields.pf_resource_value_type, tvbuf:range(pos,2))
                        pos = pos + 2
                        resource_tree:add(ssp_fields.pf_resource_service_group, tvbuf:range(pos,4))
                        pos = pos + 4
                    else
                        resource_tree:add("Unknown Resource Type. Check SSP spec.")
                        break
                    end
                    res_count = res_count + 1
                else
                    resource_tree:add("Unsupported Resource Type.")
                end
            end
        end
        -- private data
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        if (resource_count ~= 0) then
            pos = pos + 2
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
            local protocol_id = tvbuf:range(pos,1):uint()
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
            pos = pos + 1
            -- parse descriptors based on version 2 or 1 of SSP spec
            -- SSP version 2
            if (protocol_id == 2) then
                local folder_tree = tree:add("Service Gateway")
                folder_tree:add(ssp_fields.pf_sg, tvbuf:range(pos,16))
                pos = pos + 16
                folder_tree:add(ssp_fields.pf_sg_data_length, tvbuf:range(pos,4))
                pos = pos + 4
                folder_tree:add(ssp_fields.pf_sg_service, tvbuf:range(pos,16))
                pos = pos + 16
                folder_tree:add(ssp_fields.pf_sg_service_data_length, tvbuf:range(pos,4))
                --local sg_service_data_length = tvbuf:range(pos,4):uint()
                --local sd_count = sg_service_data_length
                pos = pos + 4
                -- service data
                local service_tree = folder_tree:add("Service Data")
                service_tree:add(ssp_fields.pf_descriptor_count, tvbuf:range(pos,1))
                local desc_count = tvbuf:range(pos,1):uint()
                pos = pos + 1
                for j=desc_count,1,-1 do
                    local desc_tag = tvbuf:range(pos,1):uint()
                    if (desc_tag == 1) then
                        local desc_tree = service_tree:add("Asset ID")
                        desc_tree:add(ssp_fields.pf_desc_asset_id_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_asset_id_length, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_collection_id_data, tvbuf:range(pos,4))
                        pos = pos + 4
                        desc_tree:add(ssp_fields.pf_desc_asset_id_data, tvbuf:range(pos,4))
                        pos = pos + 4
                    elseif (desc_tag == 2) then
                        local desc_tree = service_tree:add("Node Group ID")
                        desc_tree:add(ssp_fields.pf_desc_nodegroup_id_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_nodegroup_id_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_nodegroup_id_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    elseif (desc_tag == 3) then
                        local desc_tree = service_tree:add("IP")
                        desc_tree:add(ssp_fields.pf_desc_ip_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_ip_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        if desc_length > 4 then
                            desc_tree:add(ssp_fields.pf_desc_ip_data_port, tvbuf:range(pos,2))
                            pos = pos + 2
                            desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,4))
                            pos = pos + 4
                        else
                            desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,desc_length))
                            pos = pos + desc_length
                        end
                    elseif (desc_tag == 4) then
                        local desc_tree = service_tree:add("Stream Handle")
                        desc_tree:add(ssp_fields.pf_desc_stream_handle_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_stream_handle_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_stream_handle_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    elseif (desc_tag == 6) then
                        local desc_tree = service_tree:add("Application Response")
                        desc_tree:add(ssp_fields.pf_desc_app_response_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_app_response_length, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_app_response_purchase_type, tvbuf:range(pos,1))
                        local purchase_type = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        -- response failure
                        if purchase_type == 1 then
                            desc_tree:add(ssp_fields.pf_desc_app_response_failure_code, tvbuf:range(pos,1))
                            pos = pos + 1
                        -- SVOD response  
                        elseif purchase_type == 2 then
                            local num_subs = tvbuf:range(pos,1):uint()
                            local num_subs = num_subs - 32
                            desc_tree:add(ssp_fields.pf_desc_app_response_num_subs, num_subs)
                            pos = pos + 1
                            local subs_tree = desc_tree:add("Subscription/Authorization List")
                            if num_subs > 0 then
                                for i=num_subs,1,-1 do
                                    subs_tree:add(ssp_fields.pf_desc_app_response_offering_id, tvbuf:range(pos,4))
                                    pos = pos + 4
                                    subs_tree:add(ssp_fields.pf_desc_app_response_sub_expiry, tvbuf:range(pos,4))
                                    pos = pos + 4
                                end
                            end
                        -- purchase or subscription on demand
                        -- purchase response
                        elseif (purchase_type == 3) then
                            desc_tree:add(ssp_fields.pf_desc_app_response_purchase_id, tvbuf:range(pos,4))
                            pos = pos + 4
                            desc_tree:add(ssp_fields.pf_desc_app_response_offering_id, tvbuf:range(pos,4))
                            pos = pos + 4
                        elseif (purchase_type == 5) then
                            bytes_remaining = pktlen - pos
                            if bytes_remaining > 0 then
                                desc_tree:add(ssp_fields.pf_desc_app_response_purchase_id, tvbuf:range(pos,4))
                                pos = pos + 4
                                desc_tree:add(ssp_fields.pf_desc_app_response_offering_id, tvbuf:range(pos,4))
                                pos = pos + 4
                            end
                        else
                            --stop parsing
                            tree:add("Unknown purchase type, check Private Data spec")
                        end
                    elseif (desc_tag == 240) then
                        local desc_tree = service_tree:add("Transport Stream ID")
                        desc_tree:add(ssp_fields.pf_desc_tsid_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_tsid_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_tsid_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    else
                        tree:add("Unknown Descriptor, Check SSP spec!")
                        break
                    end
                end
                bytes_remaining = pktlen - pos
                if bytes_remaining > 0 then
                    folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
                end
            -- SSP version 1
            elseif (protocol_id == 1) then
                -- descriptors
                local folder_tree = tree:add("Descriptors")
                folder_tree:add(ssp_fields.pf_descriptor_count, tvbuf:range(pos,1))
                local desc_count = tvbuf:range(pos,1):uint()
                pos = pos + 1
                for i=desc_count,1,-1 do
                    local desc_tag = tvbuf:range(pos,1):uint()
                    if (desc_tag == 1) then
                        local desc_tree = folder_tree:add("Asset ID")
                        desc_tree:add(ssp_fields.pf_desc_asset_id_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_asset_id_length, tvbuf:range(pos,1))
                        --local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_collection_id_data, tvbuf:range(pos,4))
                        pos = pos + 4
                        desc_tree:add(ssp_fields.pf_desc_asset_id_data, tvbuf:range(pos,4))
                        pos = pos + 4
                    elseif (desc_tag == 2) then
                        local desc_tree = folder_tree:add("Node Group ID")
                        desc_tree:add(ssp_fields.pf_desc_nodegroup_id_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_nodegroup_id_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_nodegroup_id_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    elseif (desc_tag == 3) then
                        local desc_tree = folder_tree:add("IP")
                        desc_tree:add(ssp_fields.pf_desc_ip_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_ip_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        if desc_length > 4 then
                            desc_tree:add(ssp_fields.pf_desc_ip_data_port, tvbuf:range(pos,2))
                            pos = pos + 2
                            desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,4))
                            pos = pos + 4
                        else
                            desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,desc_length))
                            pos = pos + desc_length
                        end
                    elseif (desc_tag == 4) then
                        local desc_tree = folder_tree:add("Stream Handle")
                        desc_tree:add(ssp_fields.pf_desc_stream_handle_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_stream_handle_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_stream_handle_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    elseif (desc_tag == 6) then
                        local desc_tree = folder_tree:add("Application Response")
                        desc_tree:add(ssp_fields.pf_desc_app_response_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_app_response_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_app_response_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    elseif (desc_tag == 240) then
                        local desc_tree = service_tree:add("Transport Stream ID")
                        desc_tree:add(ssp_fields.pf_desc_tsid_tag, tvbuf:range(pos,1))
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_tsid_length, tvbuf:range(pos,1))
                        local desc_length = tvbuf:range(pos,1):uint()
                        pos = pos + 1
                        desc_tree:add(ssp_fields.pf_desc_tsid_data, tvbuf:range(pos,desc_length))
                        pos = pos + desc_length
                    else
                        tree:add("Unknown Descriptor, Check SSP spec!")
                        break
                    end
                end
                bytes_remaining = pktlen - pos
                if bytes_remaining > 0 then
                    folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
                end
            else
                tree:add("Unknown Protocol ID, Check SSP spec!")
            end
        end
        
    --------------------------------------
    --  Client Session Release Request  --
    --------------------------------------
    elseif messageid == 0x4020 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Session Release Request (CSRR), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Reason Code")
        folder_tree:add(ssp_fields.pf_reason, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        pdlen = tvbuf:range(pos,2):uint()
        pos = pos + 2
        if pdlen > 0 then
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
            pos = pos + 1
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        end

    --------------------------------------
    --  Client Session Release Confirm  --
    --------------------------------------
    elseif messageid == 0x4021 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Session Release Confirm (CSRC), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Response Code")
        folder_tree:add(ssp_fields.pf_response, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        pdlen = tvbuf:range(pos,2):uint()
        pos = pos + 2
        if pdlen > 0 then
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
            pos = pos + 1
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        end

    -----------------------------------------
    --  Client Session Release Indication  --
    -----------------------------------------
    elseif messageid == 0x4022 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Session Release Indication (CSRI), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Reason Code")
        folder_tree:add(ssp_fields.pf_reason, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        local pdlen = tvbuf:range(pos,2):uint()
        pos = pos + 2
        if pdlen > 0 then
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(28,1))
            local protocol_id = tvbuf:range(28,1):uint()
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(29,1))
            pos = pos + 1
            if (protocol_id == 2) then
                local folder_tree = tree:add("Service Gateway")
                folder_tree:add(ssp_fields.pf_sg, tvbuf:range(pos,16))
                pos = pos + 16
                folder_tree:add(ssp_fields.pf_sg_data_length, tvbuf:range(pos,4))
                pos = pos + 4
                folder_tree:add(ssp_fields.pf_sg_service, tvbuf:range(pos,16))
                pos = pos + 16
                folder_tree:add(ssp_fields.pf_sg_service_data_length, tvbuf:range(pos,4))
                pos = pos + 4
                -- service data (descriptors)
                local service_tree = folder_tree:add("Service Data")
                service_tree:add(ssp_fields.pf_descriptor_count, tvbuf:range(pos,1))
                local desc_count = tvbuf:range(pos,1):uint()
                pos = pos + 1
                if desc_count > 0 then
                    for j=desc_count,1,-1 do
                        local desc_tag = tvbuf:range(pos,1):uint()
                        --folder_tree:add(ssp_fields.pf_debug,desc_tag)
                        if (desc_tag == 1) then
                            local desc_tree = service_tree:add("Asset ID")
                            desc_tree:add(ssp_fields.pf_desc_asset_id_tag, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_asset_id_length, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_collection_id_data, tvbuf:range(pos,4))
                            pos = pos + 4
                            desc_tree:add(ssp_fields.pf_desc_asset_id_data, tvbuf:range(pos,4))
                            pos = pos + 4
                        elseif (desc_tag == 2) then
                            local desc_tree = service_tree:add("Node Group ID")
                            desc_tree:add(ssp_fields.pf_desc_nodegroup_id_tag, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_nodegroup_id_length, tvbuf:range(pos,1))
                            local desc_length = tvbuf:range(pos,1):uint()
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_nodegroup_id_data, tvbuf:range(pos,desc_length))
                            pos = pos + desc_length
                        elseif (desc_tag == 3) then
                            local desc_tree = service_tree:add("IP")
                            desc_tree:add(ssp_fields.pf_desc_ip_tag, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_ip_length, tvbuf:range(pos,1))
                            local desc_length = tvbuf:range(pos,1):uint()
                            pos = pos + 1
                            if desc_length > 4 then
                                desc_tree:add(ssp_fields.pf_desc_ip_data_port, tvbuf:range(pos,2))
                                pos = pos + 2
                                desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,4))
                                pos = pos + 4
                            else
                                desc_tree:add(ssp_fields.pf_desc_ip_data, tvbuf:range(pos,desc_length))
                                pos = pos + desc_length
                            end
                        elseif (desc_tag == 4) then
                            local desc_tree = service_tree:add("Stream Handle")
                            desc_tree:add(ssp_fields.pf_desc_stream_handle_tag, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_stream_handle_length, tvbuf:range(pos,1))
                            local desc_length = tvbuf:range(pos,1):uint()
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_stream_handle_data, tvbuf:range(pos,desc_length))
                            pos = pos + desc_length
                        elseif (desc_tag == 5) then
                            local desc_tree = service_tree:add("Application Request")
                            desc_tree:add(ssp_fields.pf_desc_app_request_tag, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_app_request_length, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_app_request_purchase_type, tvbuf:range(pos,1))
                            local purchase_type = tvbuf:range(pos,1):uint()
                            pos = pos + 1
                            if purchase_type == 4 then
                                desc_tree:add(ssp_fields.pf_desc_app_request_rental_list_start, tvbuf:range(pos,1))
                                pos = pos + 1
                                desc_tree:add(ssp_fields.pf_desc_app_request_rental_list_count, tvbuf:range(pos,1))
                                pos = pos + 1
                            elseif purchase_type == 11 then
                                desc_tree:add(ssp_fields.pf_desc_app_request_service_name, tvbuf:range(pos,16))
                                pos = pos + 16
                            end
                        elseif (desc_tag == 6) then
                            local desc_tree = service_tree:add("Application Response")
                            desc_tree:add(ssp_fields.pf_desc_app_response_tag, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_app_response_length, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_app_response_purchase_type, tvbuf:range(pos,1))
                            local purchase_type = tvbuf:range(pos,1):uint()
                            pos = pos + 1
                            -- response failure
                            if purchase_type == 1 then
                                desc_tree:add(ssp_fields.pf_desc_app_response_failure_code, tvbuf:range(pos,1))
                                pos = pos + 1
                            -- SVOD response  
                            elseif purchase_type == 2 then
                                local num_subs = tvbuf:range(pos,1):uint()
                                local num_subs = num_subs - 32
                                desc_tree:add(ssp_fields.pf_desc_app_response_num_subs, num_subs)
                                pos = pos + 1
                                local subs_tree = desc_tree:add("Subscription/Authorization List")
                                if num_subs > 0 then
                                    for i=num_subs,1,-1 do
                                        subs_tree:add(ssp_fields.pf_desc_app_response_offering_id, tvbuf:range(pos,4))
                                        pos = pos + 4
                                        subs_tree:add(ssp_fields.pf_desc_app_response_sub_expiry, tvbuf:range(pos,4))
                                        pos = pos + 4
                                    end
                                end
                            -- purchase or subscription on demand
                            -- purchase response
                            elseif (purchase_type == 3) or (purchase_type == 5) then
                                desc_tree:add(ssp_fields.pf_desc_app_response_purchase_id, tvbuf:range(pos,4))
                                pos = pos + 4
                                desc_tree:add(ssp_fields.pf_desc_app_response_offering_id, tvbuf:range(pos,4))
                                pos = pos + 4
                            else
                                --stop parsing
                                tree:add("Unknown purchase type, check Private Data spec")
                            end
                        elseif (desc_tag == 17) then
                             local desc_tree = service_tree:add("Folder ID")
                             desc_tree:add(ssp_fields.pf_desc_folderid_tag, tvbuf:range(pos,1))
                             pos = pos + 1
                             desc_tree:add(ssp_fields.pf_desc_folderid_length, tvbuf:range(pos,1))
                             local desc_length = tvbuf:range(pos,1):uint()
                             pos = pos + 1
                             desc_tree:add(ssp_fields.pf_desc_folderid_data, tvbuf:range(pos,desc_length))
                             pos = pos + desc_length
                        elseif (desc_tag == 240) then
                            local desc_tree = service_tree:add("Transport Stream ID")
                            desc_tree:add(ssp_fields.pf_desc_tsid_tag, tvbuf:range(pos,1))
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_tsid_length, tvbuf:range(pos,1))
                            local desc_length = tvbuf:range(pos,1):uint()
                            pos = pos + 1
                            desc_tree:add(ssp_fields.pf_desc_tsid_data, tvbuf:range(pos,desc_length))
                            pos = pos + desc_length
                        else
                            tree:add("Unknown Descriptor, Check SSP spec!")
                            break
                        end
                    end
                end
                bytes_remaining = pktlen - pos
                if bytes_remaining > 0 then
                    folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
                end
            end
        end

    ---------------------------------------
    --  Client Session Release Response  --
    ---------------------------------------
    elseif messageid == 0x4023 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Session Release Response (CSRR), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Response Code")
        folder_tree:add(ssp_fields.pf_response, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        local pdlen = tvbuf:range(pos,2):uint()
        pos = pos + 2
        if pdlen > 0 then
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
            pos = pos + 1
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        end

            
    -------------------------------------
    --  Client Status Request          --
    -------------------------------------
    elseif messageid == 0x4060 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Status Request (CSR), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Reason Code")
        folder_tree:add(ssp_fields.pf_reason, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        local pdlen = tvbuf:range(pos,2):uint()
        pos = pos + 2
        if pdlen > 0 then
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
            pos = pos + 1
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        end

        
    -------------------------------------
    --  Client Status Confirm          --
    -------------------------------------
    elseif messageid == 0x4061 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Status Confirm (CSC), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Response Code")
        folder_tree:add(ssp_fields.pf_response, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        local pdlen = tvbuf:range(pos,2):uint()
        pos = pos + 2
        if pdlen > 0 then
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
            pos = pos + 1
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        end

        
    -------------------------------------
    --  Client Proceeding Indication   --
    -------------------------------------
    elseif messageid == 0x4082 then
        local folder_tree = tree:add("Session")
        folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
        local mac = tvbuf:range(pos,6)
        pos = pos + 6
        folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(18,4))
        local session = tvbuf:range(pos,4):uint()
        pos = pos + 4
        pktinfo.cols.info = "Client Proceeding Indication (CPI), mac="..mac .. ", session="..session
        local folder_tree = tree:add("Reason Code")
        folder_tree:add(ssp_fields.pf_reason, tvbuf:range(pos,2))
        pos = pos + 2
        local folder_tree = tree:add("User Private Data")
        folder_tree:add(ssp_fields.pf_uudata_length, tvbuf:range(pos,2))
        pos = pos + 2
        folder_tree:add(ssp_fields.pf_private_data_length, tvbuf:range(pos,2))
        local pdlen = tvbuf:range(pos,2):uint()
        pos = pos + 2
        if pdlen > 0 then
            folder_tree:add(ssp_fields.pf_protocol_id, tvbuf:range(pos,1))
            pos = pos + 1
            folder_tree:add(ssp_fields.pf_version, tvbuf:range(pos,1))
            pos = pos + 1
            bytes_remaining = pktlen - pos
            if bytes_remaining > 0 then
                folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
            end
        end

        
    -----------------------------------------
    --  Client Session InProgress Request  --
    -----------------------------------------
    elseif messageid == 0x40b0 then
        local folder_tree = tree:add("Session")
        pktinfo.cols.info = "Client Session In-Progress Request (CSIR)"
        folder_tree:add(ssp_fields.pf_session_count, tvbuf:range(pos,2))
        local session_count = tvbuf:range(pos,2):uint()
        pos = pos + 2
        for i=session_count,1,-1 do
            folder_tree:add(ssp_fields.pf_stb_address, tvbuf:range(pos,6))
            pos = pos + 6
            folder_tree:add(ssp_fields.pf_session_number, tvbuf:range(pos,4))
            pos = pos + 4
        end
        bytes_remaining = pktlen - pos
        if bytes_remaining > 0 then
            folder_tree:add(ssp_fields.pf_unknown, tvbuf:range(pos,bytes_remaining))
        end

  
    -- when none of the messages are found
    else
        folder_tree:add("ERROR: Unknown SSP Message ID!")
    end
end

----------------------------------------
-- Need to have the protocol dissection invoked for a specific UDP port,
-- so get the UDP dissector table and add the protocol to it

DissectorTable.get("udp.port"):add(default_settings.port, twcssp)

----------------------------------------

local function heur_dissect_ssp(tvbuf,pktinfo,root)
    dprint2("heur_dissect_ssp called")
     -- Don't run this if disabled in preferences
    if not default_settings.heur_enabled then
        return false
    end
    if tvbuf:len() < SSP_HDR_LEN then
        dprint("heur_dissect_ssp: tvb shorter than SSP_HDR_LEN of: ",SSP_HDR_LEN)
        return false
    end
    
    -- Get SSP header data
    local tvbr = tvbuf:range(0,SSP_HDR_LEN)

    -- Check for valid DSMCC Descriminator (0x11) and Type (0x02)
    local dsmcc_desc = tvbr:range(0,1):uint()
    if dsmcc_desc ~= 17 then
        return false
    end
    local dsmcc_type = tvbr:range(1,1):uint()
    if dsmcc_type ~= 2 then
        return false
    end
    
    -- Check for valid SSP Message ID's
    local msg_id = tvbr:range(2,2)
    if (msg_id ~= 0x4010) and (msg_id ~= 0x4011) and (msg_id ~= 0x40b0) and (msg_id ~= 0x4020) and (msg_id ~= 0x4021) and (msg_id ~= 0x4022) and (msg_id ~= 0x4023) and (msg_id ~= 0x4060) and (msg_id ~= 0x4061) and (msg_id ~= 0x4082) then
        dprint("heur_dissect_ssp: Unsupported Message ID: ", msg_id)
        tree:add("Unsupported Message ID: ", msg_id)
        return false
    end
    
    twcssp.dissector(tvbuf,pktinfo,root)
    pktinfo.conversation = twcssp
    
    return true
end

-- now register that heuristic dissector into the UDP heuristic list
twcssp:register_heuristic("udp",heur_dissect_ssp)

----------------------------------------
-- Dissection End
-- The protocol (Proto) gets automatically registered after the script finishes loading.
----------------------------------------
