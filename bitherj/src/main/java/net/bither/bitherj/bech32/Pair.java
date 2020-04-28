package net.bither.bitherj.bech32;

class Pair<L, R> {
    private L l;
    private R r;

    private Pair() {
    }

    public static <L, R> Pair<L, R> of(L l, R r) {
        Pair pair = new Pair();
        pair.l = l;
        pair.r = r;
        return pair;
    }

    public R getRight() {
        return r;
    }

    public L getLeft() {
        return l;
    }
}
