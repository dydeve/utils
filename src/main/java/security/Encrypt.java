package security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * reference: org.apache.tomcat.util.security.*
 *
 * A thread safe wrapper around {@link MessageDigest} that does not make use
 * of ThreadLocal and - broadly - only creates enough MessageDigest objects
 * to satisfy the concurrency requirements.
 */
public class Encrypt {

    public static final String MD5 = "MD5";
    public static final String SHA1 = "SHA-1";

    private final String algorithm;
    private final Queue<MessageDigest> queue;

    /**
     * init algorithm and queue
     * @param algorithm name of algorithm, like "MD5", "SHA-1"...
     * @param queue save MessageDigest instance, recommend {@link java.util.concurrent.BlockingQueue}, {@link java.util.concurrent.ConcurrentLinkedQueue}
     * @throws NoSuchAlgorithmException if no such algorithm
     */
    public Encrypt(String algorithm, Queue<MessageDigest> queue) throws NoSuchAlgorithmException {
        Objects.requireNonNull(queue, "messageDigest queue can't be null!");

        if (!BlockingQueue.class.isAssignableFrom(queue.getClass()) && !ConcurrentLinkedQueue.class.isAssignableFrom(queue.getClass())) {
            throw new IllegalArgumentException("queue must be BlockingQueue or ConcurrentLinkedQueue");
        }

        MessageDigest md = MessageDigest.getInstance(algorithm);

        this.algorithm = algorithm;
        this.queue = queue;

        queue.add(md);

    }

    public byte[] digest(byte[] input) {

        /**
         * Retrieves and removes the head of this queue,
         * or returns {@code null} if this queue is empty.
         */
        MessageDigest md = queue.poll();
        if (md == null) {
            try {
                md = MessageDigest.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                //we call the constructor firstly, so it is impossible that exception happens here. do nothing
                ;
            }
        }

        md.update(input);
        byte[] output = md.digest();//cache it to promise thread-safe
        //if exception happens, we don't need to add md to queue.

        /**
         * Inserts the specified element into this queue if it is possible to do so
         * immediately without violating capacity restrictions, returning
         * {@code true} upon success and throwing an {@code IllegalStateException}
         * if no space is currently available.
         */
        queue.add(md);
        return output;
    }

    /**
     * Encode an MD5 digest into a String.
     * <p>
     * The 128 bit MD5 hash is converted into a 32 character long String.
     * Each character of the String is the hexadecimal representation of 4 bits
     * of the digest.
     *
     * @author Remy Maucherat
     */
    public static final class MD5Encoder {

        private MD5Encoder() {
            // Hide default constructor for utility class
        }


        private static final char[] hexadecimal = {'0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


        /**
         * Encodes the 128 bit (16 bytes) MD5 into a 32 character String.
         *
         * @param binaryData Array containing the digest
         *
         * @return Encoded MD5, or null if encoding failed
         */
        public static String encode(byte[] binaryData) {

            if (binaryData.length != 16)
                return null;

            char[] buffer = new char[32];

            for (int i=0; i<16; i++) {
                int low = binaryData[i] & 0x0f;
                int high = (binaryData[i] & 0xf0) >> 4;
                buffer[i*2] = hexadecimal[high];
                buffer[i*2 + 1] = hexadecimal[low];
            }

            return new String(buffer);
        }
    }

}
