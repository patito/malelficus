-- Author: Tiago Natel de Moura
-- package: malelficus

local modname = ...
local malelficus = {}

local hex = require "hex"
local asm = require "asm"

if #_G > 0 then
   _G[modname] = malelficus
   _G[modname]["hex"] = hex
   _G[modname]["asm"] = asm
end

return malelficus

