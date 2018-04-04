@ stdcall wined3d_mutex_lock()
@ stdcall wined3d_mutex_unlock()

@ cdecl wined3d_calculate_format_pitch(ptr long long)
@ cdecl wined3d_check_depth_stencil_match(ptr long long long long)
@ cdecl wined3d_check_device_format(ptr ptr long long long long long long)
@ cdecl wined3d_check_device_format_conversion(ptr long long long)
@ cdecl wined3d_check_device_multisample_type(ptr long long long long ptr)
@ cdecl wined3d_check_device_type(ptr ptr long long long long)
@ cdecl wined3d_create(long)
@ cdecl wined3d_decref(ptr)
@ cdecl wined3d_get_adapter(ptr long)
@ cdecl wined3d_get_adapter_count(ptr)
@ cdecl wined3d_get_device_caps(ptr long ptr)
@ cdecl wined3d_incref(ptr)
@ cdecl wined3d_register_software_device(ptr ptr)
@ cdecl wined3d_register_window(ptr ptr ptr long)
@ cdecl wined3d_unregister_windows(ptr)

@ cdecl wined3d_adapter_get_identifier(ptr long ptr)
@ cdecl wined3d_adapter_get_output(ptr long)
@ cdecl wined3d_adapter_get_output_count(ptr)

@ cdecl wined3d_blend_state_create(ptr ptr ptr ptr ptr)
@ cdecl wined3d_blend_state_decref(ptr)
@ cdecl wined3d_blend_state_get_parent(ptr)
@ cdecl wined3d_blend_state_incref(ptr)

@ cdecl wined3d_buffer_create(ptr ptr ptr ptr ptr ptr)
@ cdecl wined3d_buffer_decref(ptr)
@ cdecl wined3d_buffer_get_parent(ptr)
@ cdecl wined3d_buffer_get_resource(ptr)
@ cdecl wined3d_buffer_incref(ptr)

@ cdecl wined3d_device_acquire_focus_window(ptr ptr)
@ cdecl wined3d_device_apply_stateblock(ptr ptr)
@ cdecl wined3d_device_begin_scene(ptr)
@ cdecl wined3d_device_clear(ptr long ptr long ptr float long)
@ cdecl wined3d_device_clear_rendertarget_view(ptr ptr ptr long ptr float long)
@ cdecl wined3d_device_clear_unordered_access_view_uint(ptr ptr ptr)
@ cdecl wined3d_device_copy_resource(ptr ptr ptr)
@ cdecl wined3d_device_copy_sub_resource_region(ptr ptr long long long long ptr long ptr long)
@ cdecl wined3d_device_copy_uav_counter(ptr ptr long ptr)
@ cdecl wined3d_device_create(ptr ptr long ptr long long ptr long ptr ptr)
@ cdecl wined3d_device_decref(ptr)
@ cdecl wined3d_device_dispatch_compute(ptr long long long)
@ cdecl wined3d_device_dispatch_compute_indirect(ptr ptr long)
@ cdecl wined3d_device_draw_indexed_primitive(ptr long long)
@ cdecl wined3d_device_draw_indexed_primitive_instanced(ptr long long long long)
@ cdecl wined3d_device_draw_indexed_primitive_instanced_indirect(ptr ptr long)
@ cdecl wined3d_device_draw_primitive(ptr long long)
@ cdecl wined3d_device_draw_primitive_instanced(ptr long long long long)
@ cdecl wined3d_device_draw_primitive_instanced_indirect(ptr ptr long)
@ cdecl wined3d_device_end_scene(ptr)
@ cdecl wined3d_device_evict_managed_resources(ptr)
@ cdecl wined3d_device_flush(ptr)
@ cdecl wined3d_device_get_available_texture_mem(ptr)
@ cdecl wined3d_device_get_blend_state(ptr ptr)
@ cdecl wined3d_device_get_clip_status(ptr ptr)
@ cdecl wined3d_device_get_compute_shader(ptr)
@ cdecl wined3d_device_get_constant_buffer(ptr long long)
@ cdecl wined3d_device_get_creation_parameters(ptr ptr)
@ cdecl wined3d_device_get_cs_resource_view(ptr long)
@ cdecl wined3d_device_get_cs_sampler(ptr long)
@ cdecl wined3d_device_get_cs_uav(ptr long)
@ cdecl wined3d_device_get_depth_stencil_view(ptr)
@ cdecl wined3d_device_get_device_caps(ptr ptr)
@ cdecl wined3d_device_get_display_mode(ptr long ptr ptr)
@ cdecl wined3d_device_get_domain_shader(ptr)
@ cdecl wined3d_device_get_ds_resource_view(ptr long)
@ cdecl wined3d_device_get_ds_sampler(ptr long)
@ cdecl wined3d_device_get_feature_level(ptr)
@ cdecl wined3d_device_get_gamma_ramp(ptr long ptr)
@ cdecl wined3d_device_get_geometry_shader(ptr)
@ cdecl wined3d_device_get_gs_resource_view(ptr long)
@ cdecl wined3d_device_get_gs_sampler(ptr long)
@ cdecl wined3d_device_get_hs_resource_view(ptr long)
@ cdecl wined3d_device_get_hs_sampler(ptr long)
@ cdecl wined3d_device_get_hull_shader(ptr)
@ cdecl wined3d_device_get_index_buffer(ptr ptr ptr)
@ cdecl wined3d_device_get_max_frame_latency(ptr)
@ cdecl wined3d_device_get_npatch_mode(ptr)
@ cdecl wined3d_device_get_pixel_shader(ptr)
@ cdecl wined3d_device_get_predication(ptr ptr)
@ cdecl wined3d_device_get_primitive_type(ptr ptr ptr)
@ cdecl wined3d_device_get_ps_resource_view(ptr long)
@ cdecl wined3d_device_get_ps_sampler(ptr long)
@ cdecl wined3d_device_get_raster_status(ptr long ptr)
@ cdecl wined3d_device_get_rasterizer_state(ptr)
@ cdecl wined3d_device_get_render_state(ptr long)
@ cdecl wined3d_device_get_rendertarget_view(ptr long)
@ cdecl wined3d_device_get_scissor_rects(ptr ptr ptr)
@ cdecl wined3d_device_get_software_vertex_processing(ptr)
@ cdecl wined3d_device_get_stream_output(ptr long ptr)
@ cdecl wined3d_device_get_stream_source(ptr long ptr ptr ptr)
@ cdecl wined3d_device_get_swapchain(ptr long)
@ cdecl wined3d_device_get_swapchain_count(ptr)
@ cdecl wined3d_device_get_unordered_access_view(ptr long)
@ cdecl wined3d_device_get_vertex_declaration(ptr)
@ cdecl wined3d_device_get_vertex_shader(ptr)
@ cdecl wined3d_device_get_viewports(ptr ptr ptr)
@ cdecl wined3d_device_get_vs_resource_view(ptr long)
@ cdecl wined3d_device_get_vs_sampler(ptr long)
@ cdecl wined3d_device_get_wined3d(ptr)
@ cdecl wined3d_device_incref(ptr)
@ cdecl wined3d_device_process_vertices(ptr long long long ptr ptr long long)
@ cdecl wined3d_device_release_focus_window(ptr)
@ cdecl wined3d_device_reset(ptr ptr ptr ptr long)
@ cdecl wined3d_device_resolve_sub_resource(ptr ptr long ptr long long)
@ cdecl wined3d_device_set_base_vertex_index(ptr long)
@ cdecl wined3d_device_set_blend_state(ptr ptr ptr)
@ cdecl wined3d_device_set_clip_status(ptr ptr)
@ cdecl wined3d_device_set_compute_shader(ptr ptr)
@ cdecl wined3d_device_set_constant_buffer(ptr long long ptr)
@ cdecl wined3d_device_set_cs_resource_view(ptr long ptr)
@ cdecl wined3d_device_set_cs_sampler(ptr long ptr)
@ cdecl wined3d_device_set_cs_uav(ptr long ptr long)
@ cdecl wined3d_device_set_cursor_position(ptr long long long)
@ cdecl wined3d_device_set_cursor_properties(ptr long long ptr long)
@ cdecl wined3d_device_set_depth_stencil_view(ptr ptr)
@ cdecl wined3d_device_set_dialog_box_mode(ptr long)
@ cdecl wined3d_device_set_domain_shader(ptr ptr)
@ cdecl wined3d_device_set_ds_resource_view(ptr long ptr)
@ cdecl wined3d_device_set_ds_sampler(ptr long ptr)
@ cdecl wined3d_device_set_gamma_ramp(ptr long long ptr)
@ cdecl wined3d_device_set_geometry_shader(ptr ptr)
@ cdecl wined3d_device_set_gs_resource_view(ptr long ptr)
@ cdecl wined3d_device_set_gs_sampler(ptr long ptr)
@ cdecl wined3d_device_set_hs_resource_view(ptr long ptr)
@ cdecl wined3d_device_set_hs_sampler(ptr long ptr)
@ cdecl wined3d_device_set_hull_shader(ptr ptr)
@ cdecl wined3d_device_set_index_buffer(ptr ptr long long)
@ cdecl wined3d_device_set_max_frame_latency(ptr long)
@ cdecl wined3d_device_set_multithreaded(ptr)
@ cdecl wined3d_device_set_npatch_mode(ptr float)
@ cdecl wined3d_device_set_pixel_shader(ptr ptr)
@ cdecl wined3d_device_set_predication(ptr ptr long)
@ cdecl wined3d_device_set_primitive_type(ptr long long)
@ cdecl wined3d_device_set_ps_resource_view(ptr long ptr)
@ cdecl wined3d_device_set_ps_sampler(ptr long ptr)
@ cdecl wined3d_device_set_rasterizer_state(ptr ptr)
@ cdecl wined3d_device_set_render_state(ptr long long)
@ cdecl wined3d_device_set_rendertarget_view(ptr long ptr long)
@ cdecl wined3d_device_set_scissor_rects(ptr long ptr)
@ cdecl wined3d_device_set_software_vertex_processing(ptr long)
@ cdecl wined3d_device_set_stream_output(ptr long ptr long)
@ cdecl wined3d_device_set_stream_source(ptr long ptr long long)
@ cdecl wined3d_device_set_unordered_access_view(ptr long ptr long)
@ cdecl wined3d_device_set_vertex_declaration(ptr ptr)
@ cdecl wined3d_device_set_vertex_shader(ptr ptr)
@ cdecl wined3d_device_set_viewports(ptr long ptr)
@ cdecl wined3d_device_set_vs_resource_view(ptr long ptr)
@ cdecl wined3d_device_set_vs_sampler(ptr long ptr)
@ cdecl wined3d_device_show_cursor(ptr long)
@ cdecl wined3d_device_update_sub_resource(ptr ptr long ptr ptr long long long)
@ cdecl wined3d_device_update_texture(ptr ptr ptr)
@ cdecl wined3d_device_validate_device(ptr ptr)

@ cdecl wined3d_output_find_closest_matching_mode(ptr ptr)
@ cdecl wined3d_output_get_adapter(ptr)
@ cdecl wined3d_output_get_desc(ptr ptr)
@ cdecl wined3d_output_get_display_mode(ptr ptr ptr)
@ cdecl wined3d_output_get_mode(ptr long long long ptr)
@ cdecl wined3d_output_get_mode_count(ptr long long)
@ cdecl wined3d_output_get_raster_status(ptr ptr)
@ cdecl wined3d_output_release_ownership(ptr)
@ cdecl wined3d_output_set_display_mode(ptr ptr)
@ cdecl wined3d_output_take_ownership(ptr long)

@ cdecl wined3d_palette_create(ptr long long ptr ptr)
@ cdecl wined3d_palette_decref(ptr)
@ cdecl wined3d_palette_get_entries(ptr long long long ptr)
@ cdecl wined3d_palette_apply_to_dc(ptr ptr)
@ cdecl wined3d_palette_incref(ptr)
@ cdecl wined3d_palette_set_entries(ptr long long long ptr)

@ cdecl wined3d_query_create(ptr long ptr ptr ptr)
@ cdecl wined3d_query_decref(ptr)
@ cdecl wined3d_query_get_data(ptr ptr long long)
@ cdecl wined3d_query_get_data_size(ptr)
@ cdecl wined3d_query_get_parent(ptr)
@ cdecl wined3d_query_get_type(ptr)
@ cdecl wined3d_query_incref(ptr)
@ cdecl wined3d_query_issue(ptr long)

@ cdecl wined3d_rasterizer_state_create(ptr ptr ptr ptr ptr)
@ cdecl wined3d_rasterizer_state_decref(ptr)
@ cdecl wined3d_rasterizer_state_get_parent(ptr)
@ cdecl wined3d_rasterizer_state_incref(ptr)

@ cdecl wined3d_resource_get_desc(ptr ptr)
@ cdecl wined3d_resource_get_parent(ptr)
@ cdecl wined3d_resource_get_priority(ptr)
@ cdecl wined3d_resource_map(ptr long ptr ptr long)
@ cdecl wined3d_resource_preload(ptr)
@ cdecl wined3d_resource_set_parent(ptr ptr)
@ cdecl wined3d_resource_set_priority(ptr long)
@ cdecl wined3d_resource_unmap(ptr long)

@ cdecl wined3d_rendertarget_view_create(ptr ptr ptr ptr ptr)
@ cdecl wined3d_rendertarget_view_create_from_sub_resource(ptr long ptr ptr ptr)
@ cdecl wined3d_rendertarget_view_decref(ptr)
@ cdecl wined3d_rendertarget_view_get_parent(ptr)
@ cdecl wined3d_rendertarget_view_get_resource(ptr)
@ cdecl wined3d_rendertarget_view_get_sub_resource_parent(ptr)
@ cdecl wined3d_rendertarget_view_incref(ptr)
@ cdecl wined3d_rendertarget_view_set_parent(ptr ptr)

@ cdecl wined3d_sampler_create(ptr ptr ptr ptr ptr)
@ cdecl wined3d_sampler_decref(ptr)
@ cdecl wined3d_sampler_get_parent(ptr)
@ cdecl wined3d_sampler_incref(ptr)

@ cdecl wined3d_shader_create_cs(ptr ptr ptr ptr ptr)
@ cdecl wined3d_shader_create_ds(ptr ptr ptr ptr ptr)
@ cdecl wined3d_shader_create_gs(ptr ptr ptr ptr ptr ptr)
@ cdecl wined3d_shader_create_hs(ptr ptr ptr ptr ptr)
@ cdecl wined3d_shader_create_ps(ptr ptr ptr ptr ptr)
@ cdecl wined3d_shader_create_vs(ptr ptr ptr ptr ptr)
@ cdecl wined3d_shader_decref(ptr)
@ cdecl wined3d_shader_get_byte_code(ptr ptr ptr)
@ cdecl wined3d_shader_get_parent(ptr)
@ cdecl wined3d_shader_incref(ptr)
@ cdecl wined3d_shader_set_local_constants_float(ptr long ptr long)

@ cdecl wined3d_shader_resource_view_create(ptr ptr ptr ptr ptr)
@ cdecl wined3d_shader_resource_view_decref(ptr)
@ cdecl wined3d_shader_resource_view_generate_mipmaps(ptr)
@ cdecl wined3d_shader_resource_view_get_parent(ptr)
@ cdecl wined3d_shader_resource_view_incref(ptr)

@ cdecl wined3d_stateblock_apply(ptr ptr)
@ cdecl wined3d_stateblock_capture(ptr ptr)
@ cdecl wined3d_stateblock_create(ptr ptr long ptr)
@ cdecl wined3d_stateblock_decref(ptr)
@ cdecl wined3d_stateblock_get_light(ptr long ptr ptr)
@ cdecl wined3d_stateblock_get_state(ptr)
@ cdecl wined3d_stateblock_incref(ptr)
@ cdecl wined3d_stateblock_init_contained_states(ptr)
@ cdecl wined3d_stateblock_multiply_transform(ptr long ptr)
@ cdecl wined3d_stateblock_reset(ptr)
@ cdecl wined3d_stateblock_set_base_vertex_index(ptr long)
@ cdecl wined3d_stateblock_set_clip_plane(ptr long ptr)
@ cdecl wined3d_stateblock_set_index_buffer(ptr ptr long)
@ cdecl wined3d_stateblock_set_light(ptr long ptr)
@ cdecl wined3d_stateblock_set_light_enable(ptr long long)
@ cdecl wined3d_stateblock_set_material(ptr ptr)
@ cdecl wined3d_stateblock_set_pixel_shader(ptr ptr)
@ cdecl wined3d_stateblock_set_ps_consts_b(ptr long long ptr)
@ cdecl wined3d_stateblock_set_ps_consts_f(ptr long long ptr)
@ cdecl wined3d_stateblock_set_ps_consts_i(ptr long long ptr)
@ cdecl wined3d_stateblock_set_render_state(ptr long long)
@ cdecl wined3d_stateblock_set_sampler_state(ptr long long long)
@ cdecl wined3d_stateblock_set_scissor_rect(ptr ptr)
@ cdecl wined3d_stateblock_set_stream_source(ptr long ptr long long)
@ cdecl wined3d_stateblock_set_stream_source_freq(ptr long long)
@ cdecl wined3d_stateblock_set_texture(ptr long ptr)
@ cdecl wined3d_stateblock_set_texture_stage_state(ptr long long long)
@ cdecl wined3d_stateblock_set_transform(ptr long ptr)
@ cdecl wined3d_stateblock_set_vertex_declaration(ptr ptr)
@ cdecl wined3d_stateblock_set_vertex_shader(ptr ptr)
@ cdecl wined3d_stateblock_set_viewport(ptr ptr)
@ cdecl wined3d_stateblock_set_vs_consts_b(ptr long long ptr)
@ cdecl wined3d_stateblock_set_vs_consts_f(ptr long long ptr)
@ cdecl wined3d_stateblock_set_vs_consts_i(ptr long long ptr)

@ cdecl wined3d_swapchain_create(ptr ptr ptr ptr ptr)
@ cdecl wined3d_swapchain_decref(ptr)
@ cdecl wined3d_swapchain_get_back_buffer(ptr long)
@ cdecl wined3d_swapchain_get_device(ptr)
@ cdecl wined3d_swapchain_get_display_mode(ptr ptr ptr)
@ cdecl wined3d_swapchain_get_front_buffer_data(ptr ptr long)
@ cdecl wined3d_swapchain_get_gamma_ramp(ptr ptr)
@ cdecl wined3d_swapchain_get_parent(ptr)
@ cdecl wined3d_swapchain_get_desc(ptr ptr)
@ cdecl wined3d_swapchain_get_raster_status(ptr ptr)
@ cdecl wined3d_swapchain_get_state(ptr)
@ cdecl wined3d_swapchain_incref(ptr)
@ cdecl wined3d_swapchain_present(ptr ptr ptr ptr long long)
@ cdecl wined3d_swapchain_resize_buffers(ptr long long long long long long)
@ cdecl wined3d_swapchain_set_gamma_ramp(ptr long ptr)
@ cdecl wined3d_swapchain_set_palette(ptr ptr)
@ cdecl wined3d_swapchain_set_window(ptr ptr)

@ cdecl wined3d_swapchain_state_create(ptr ptr ptr)
@ cdecl wined3d_swapchain_state_destroy(ptr)
@ cdecl wined3d_swapchain_state_resize_target(ptr ptr)
@ cdecl wined3d_swapchain_state_set_fullscreen(ptr ptr ptr)

@ cdecl wined3d_texture_add_dirty_region(ptr long ptr)
@ cdecl wined3d_texture_blt(ptr long ptr ptr long ptr long ptr long)
@ cdecl wined3d_texture_create(ptr ptr long long long ptr ptr ptr ptr)
@ cdecl wined3d_texture_decref(ptr)
@ cdecl wined3d_texture_from_resource(ptr)
@ cdecl wined3d_texture_get_dc(ptr long ptr)
@ cdecl wined3d_texture_get_level_count(ptr)
@ cdecl wined3d_texture_get_lod(ptr)
@ cdecl wined3d_texture_get_overlay_position(ptr long ptr ptr)
@ cdecl wined3d_texture_get_parent(ptr)
@ cdecl wined3d_texture_get_pitch(ptr long ptr ptr)
@ cdecl wined3d_texture_get_resource(ptr)
@ cdecl wined3d_texture_get_sub_resource_desc(ptr long ptr)
@ cdecl wined3d_texture_get_sub_resource_parent(ptr long)
@ cdecl wined3d_texture_incref(ptr)
@ cdecl wined3d_texture_release_dc(ptr long ptr)
@ cdecl wined3d_texture_set_color_key(ptr long ptr)
@ cdecl wined3d_texture_set_lod(ptr long)
@ cdecl wined3d_texture_set_overlay_position(ptr long long long)
@ cdecl wined3d_texture_set_sub_resource_parent(ptr long ptr)
@ cdecl wined3d_texture_update_desc(ptr long long long long long long ptr long)
@ cdecl wined3d_texture_update_overlay(ptr long ptr ptr long ptr long)

@ cdecl wined3d_unordered_access_view_create(ptr ptr ptr ptr ptr)
@ cdecl wined3d_unordered_access_view_decref(ptr)
@ cdecl wined3d_unordered_access_view_get_parent(ptr)
@ cdecl wined3d_unordered_access_view_incref(ptr)

@ cdecl wined3d_vertex_declaration_create(ptr ptr long ptr ptr ptr)
@ cdecl wined3d_vertex_declaration_create_from_fvf(ptr long ptr ptr ptr)
@ cdecl wined3d_vertex_declaration_decref(ptr)
@ cdecl wined3d_vertex_declaration_get_parent(ptr)
@ cdecl wined3d_vertex_declaration_incref(ptr)

@ cdecl wined3d_extract_shader_input_signature_from_dxbc(ptr ptr long)

@ cdecl wined3d_access_gl_texture(ptr ptr ptr long)
@ cdecl wined3d_device_run_cs_callback(ptr ptr ptr long)
