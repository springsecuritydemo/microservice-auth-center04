package com.thtf.auth.service;

import com.thtf.auth.dao.SysUserRoleMapper;
import com.thtf.auth.model.SysUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/23 10:38
 * Version: v1.0
 * ========================
 */
@Service
public class SysUserRoleService {

    @Autowired
    private SysUserRoleMapper userRoleMapper;

    public List<SysUserRole> listByUserId(Integer userId) {
        return userRoleMapper.listByUserId(userId);
    }
}