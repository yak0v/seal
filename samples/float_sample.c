/*
 * float_sample.c — planted floating-point anomalies for the float_anomaly check
 * (a result that can be NaN or +/-Inf). Built like the other samples (x86-64 ELF,
 * -O0 -no-pie). Mark the args symbolic (mode:"symbolic", float:true) and the check
 * should find the inputs that make the result non-finite.
 */

/* divf: a/b is +/-Inf when b==0 (a!=0), and NaN when a==0 && b==0. */
float divf(float a, float b) {
    return a / b;
}

/* muld: a*b overflows to +/-Inf for large finite inputs (e.g. 1e300 * 1e300). */
double muld(double a, double b) {
    return a * b;
}

/* subd: Inf - Inf == NaN; reachable when both inputs are infinite. */
double subd(double a, double b) {
    return a - b;
}

int main(void) { return 0; }
