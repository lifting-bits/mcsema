class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGNETA = '\033[95m'
    RESET = '\033[0m'

    BG_YELLOW = '\033[43m'

def get_result_color(total, success):
    if total == 0:
        return Colors.MAGNETA
    if total == success:
        return Colors.GREEN
    if success == 0:
        return Colors.RED
    return Colors.YELLOW

def get_bin_result(result):
    if result == 1:
        return Colors.GREEN
    if result == 0:
        return Colors.RED
    return Colors.MAGNETA

def clean():
    return Colors.RESET

def c(color, message):
    return color + message + clean()

def fail():
    return Colors.RED

def succ():
    return Colors.GREEN

#TODO: Generate from static attrs
def green(message):
    return c(Colors.GREEN, message)

def red(message):
    return c(Colors.RED, message)

def yellow(message):
    return c(Colors.YELLOW, message)

def magneta(message):
    return c(Colors.MAGNETA, message)
