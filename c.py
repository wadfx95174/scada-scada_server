import a

def new_print_message(message):
    print ("NEW:", message)

a.print_message = new_print_message

a.print_message("asdasdasdasd")