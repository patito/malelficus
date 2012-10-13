-- For Writing virus, you can not use the data segment, so we need to use the
-- stack to store our strings.
-- This isn't the best choice, but is the most safe!
-- This module help in push your string into the stack

-- Author: Tiago Natel de Moura
-- package: Malelficus.asm
-- http://tiago4orion.github.com/malelficus

-- input: GABRIELLA\n
-- The result should be:
-- 	push dword 0x00000a41
-- 	push dword 0x4c4c4549
-- 	push dword 0x52424147

local modname = ...
local asm = {}

if #_G > 0 then
   _G[modname] = asm
end

local hex = require "hex"

function trim (str)
   return (str:gsub("^%s*(.-)%s*$", "%1"))
end

function asm.push_string( str, new_line )
   if new_line then
      str = string.format("%s\n", str)
   end

   -- add nil byte
   str = string.format("%s\00", str)

   str = trim(str)
   str = str:reverse()
   length = string.len(str)
   tb = {}

   strhex = hex.strhex(str)

   for i = 1, #strhex, 4 do
      if (#strhex - i) == 0 then
         io.write(string.format("push byte 0x%02x\n", strhex[i])) 
      elseif (#strhex - i) == 1 then
         io.write(string.format("push word 0x%02x%02x\n", strhex[i],
                                strhex[i+1]))
      elseif (#strhex - i) == 2 then
         io.write(string.format("push word 0x%02x%02x\n", strhex[i],
                                strhex[i+1]))
         io.write(string.format("push byte 0x%02x\n", strhex[i+2]))
      elseif (#strhex - i) >= 3 then
         io.write(string.format("push dword 0x%02x%02x%02x%02x\n",
                                strhex[i],
                                strhex[i+1],
                                strhex[i+2],
                                strhex[i+3]))
      end
   end
end


if arg and modname ~= 'asm' then
   if #arg == 0 then
      print (string.format("Usage: %s <string> [-n]", arg[0]))
      print (" -n\tInsert new line at end of the string. [optional]\n")
   else
      asm.push_string (arg[1], arg[2] == '-n')
   end
end





