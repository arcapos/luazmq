local zmq = require 'zmq'

local capabilities = {
	ipc	= 'the ipc:// protocol',
	pgm	= 'the pgm:// protocol',
	tcp	= 'the tcp:// protocol',
	tipc	= 'the tipc:// protocol',
	norm	= 'the norm:// protocol',
	curve	= 'the CURVE security mechanism',
	gssapi	= 'the GSSAPI security mechanism',
	draft	= 'the draft API',
}

for k, v in pairs(capabilities) do
	if zmq.has(k) == true then
		print('The zmq Lua module supports ' .. v)
	else
		print('The zmq Lua modules does not support ' .. v)
	end
end
