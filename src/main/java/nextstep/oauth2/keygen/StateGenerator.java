package nextstep.oauth2.keygen;

import java.security.SecureRandom;

public class StateGenerator {
    private final SecureRandom random;

    public StateGenerator() {
        this.random = new SecureRandom();
    }

    public String generateKey() {
        return generateRandomStr(8, false);
    }

    public String generateRandomStr(int length, boolean isUpperCase) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(this.random.nextInt(alphabet.length())));
        }
        return isUpperCase ? sb.toString().toUpperCase() : sb.toString().toLowerCase();
    }
}
