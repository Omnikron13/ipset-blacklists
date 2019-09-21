# Return set of items in a which are not in b
def diff(a, b):
    return {i for i in a if i not in b}


# Complement to the diff() function above
def intersect(a, b):
    return {i for i in a if i in a and i in b}
