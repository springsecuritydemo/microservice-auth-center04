package com.thtf.auth.response;

import lombok.Data;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/24 9:44
 * Version: v1.0
 * ========================
 */
@Data
public class Result<T> {
    private int code;
    private String msg;
    private T data;
}
