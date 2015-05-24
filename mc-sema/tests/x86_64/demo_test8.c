
int g_j = 1;

void foo(void) {
    return;
}

int doOp(int k) {
    int v = g_j;
    g_j += k;
    return v;
}

