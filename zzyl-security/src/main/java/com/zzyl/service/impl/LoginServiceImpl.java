package com.zzyl.service.impl;


import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.json.JSONUtil;
import com.zzyl.constant.UserCacheConstant;
import com.zzyl.exception.BaseException;
import com.zzyl.properties.JwtTokenManagerProperties;
import com.zzyl.service.ResourceService;
import com.zzyl.service.RoleService;
import com.zzyl.utils.JwtUtil;
import com.zzyl.vo.ResourceVo;
import com.zzyl.vo.RoleVo;
import com.zzyl.vo.UserVo;
import com.zzyl.vo.UserAuth;
import com.zzyl.dto.LoginDto;
import com.zzyl.service.LoginService;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class LoginServiceImpl implements LoginService {


    //认证管理器
    @Autowired
    private AuthenticationManager authenticationManager;

    //角色Service
    @Autowired
    private RoleService roleService;

    //资源Service
    @Autowired
    private ResourceService resourceService;

    //JWT
    @Autowired
    private JwtTokenManagerProperties jwtTokenManagerProperties;

    //Redis
    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     *登录
     * @param loginDto
     * @return
     */
    @Override
    public UserVo login(LoginDto loginDto) {

        UsernamePasswordAuthenticationToken upat =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(),loginDto.getPassword());
        //调用security安全框架 检验
        Authentication authenticate = authenticationManager.authenticate(upat);
        if (ObjectUtil.isEmpty(authenticate)){
            throw new BaseException("账户不存在");
        }
        UserAuth userAuth = (UserAuth) authenticate.getPrincipal();
        //安全框架返回的对象类型转换
        UserVo userVo = BeanUtil.toBean(userAuth, UserVo.class);

        //获取用户资源列表
        List<ResourceVo> resourceVoList =
                resourceService.findResourceVoListByUserId(userVo.getId());
        Set<String> collect = resourceVoList.stream()
                        .filter(res -> "r".equals(res.getResourceType()))
                        .map(ResourceVo::getRequestPath)
                        .collect(Collectors.toSet());
        userVo.setResourceRequestPaths(collect);

        //获取用户角色列表
        List<RoleVo> roleVoList = roleService.findRoleVoListByUserId(userVo.getId());
        Set<String> lableList =
                roleVoList.stream().map(RoleVo::getLabel).collect(Collectors.toSet());
        userVo.setRoleLabels(lableList);

        //颁发token
            //1.去除敏感数据
            userVo.setPassword("");
            //2.生成JwtToken
                //2.1准备数据
                Map<String,Object> map = new HashMap<>();
                map.put("currentUser", JSONUtil.toJsonStr(userVo));
        String jwtToken =
                JwtUtil.createJWT(jwtTokenManagerProperties.getBase64EncodedSecretKey()
                , jwtTokenManagerProperties.getTtl(), map);

        //生成uuid
        String uuidToken = UUID.randomUUID().toString();


        //存储数据到Redis
        String uuidTokenKey = UserCacheConstant.USER_TOKEN + userVo.getUsername();
        redisTemplate.opsForValue().set(uuidTokenKey,uuidToken);
        String jwtTokenKey = UserCacheConstant.JWT_TOKEN + uuidToken;
        redisTemplate.opsForValue().set(jwtTokenKey,jwtToken);

        //uuidToken返回前端
        userVo.setUserToken(uuidToken);

        return userVo;
    }
}
