"""
Example Script Showing how to use Alpaca Turbo for a simple bot
"""
# import the Assistant
from alpaca_turbo import Assistant

asistant = Assistant()

# This returns a generator that can be used for streaming response
result = asistant.ask_bot("hi")

# Or you can directly return the entire answer
answer = "".join(result)

print("**************")
print(answer)
print("**************")

# you can keep using this in a loop the bot remembers previous response but
# the way it's implemented is vary costly so to save performance
asistant.enable_history = False

# after disabling the history you don't need to reload the bot
# The bot will forget everything
# still the history is tracked internally so if you come up with a smart also
# that determines when to use and when to not use history this will be very helpful

result = asistant.ask_bot("what is your name?")
answer = "".join(result)

print("**************")
print(answer)
print("**************")
