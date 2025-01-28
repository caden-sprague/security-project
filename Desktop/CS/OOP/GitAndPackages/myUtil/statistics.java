package myUtil;

public class statistics {

    public static double getAverage(int[] _arr) {
        double total = 0.0;

        for (int i : _arr) {
            total += i;
        }

        return total / _arr.length;
    }

    static void sort(int[] _arr) {
        for (int i = 0; i < _arr.length-1; i++) {
            if( _arr[i] > _arr[i+1]) {
                swap(_arr, i, i+1);
            }
        }
    }

    static void swap(int[] _arr, int _pos0, int _pos1) {
        int temp = _arr[_pos0];
        _arr[_pos0] = _arr[_pos1];
        _arr[_pos1] = temp;
    }

    // should this not return a double in the case of even length?
    // median of {1,2,3,4} is 2.5
    public static int getMedian(int[] _arr) {
        /**
         * sort
         * if odd
         *      return middle val
         * if even
         *      return average of middle 2 vals
         */
        sort(_arr);


        if(_arr.length % 2 == 1) {
            return _arr[_arr.length/2];
        }
        else {
            int[] newArr = {_arr.length/2, _arr.length/2 + 1};
            return (int) getAverage(newArr);
        }
    }
    
}

