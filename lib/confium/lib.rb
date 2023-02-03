require 'ffi'

module Confium
  module Lib
    extend ::FFI::Library

    FFI_LAYOUT = {
      cfm_create: [ %i[pointer], :uint32 ],
      cfm_destroy: [ %i[pointer], :uint32 ],
      cfm_plugin_load: [ %i[pointer string string pointer pointer], :uint32 ],
      cfm_hash_create: [ %i[pointer pointer pointer pointer pointer pointer], :uint32 ],
      cfm_hash_output_size: [ %i[pointer pointer], :uint32 ],
      cfm_hash_block_size: [ %i[pointer pointer], :uint32 ],
      cfm_hash_update: [ %i[pointer pointer uint32], :uint32 ],
      cfm_hash_reset: [ %i[pointer], :uint32 ],
      cfm_hash_clone: [ %i[pointer pointer], :uint32 ],
      cfm_hash_finalize: [ %i[pointer pointer uint32], :uint32 ],
      cfm_hash_destroy: [ %i[pointer], :void ],
    }.freeze

    ffi_lib(%w[confium libconfium])

    FFI_LAYOUT.each do |func, ary|
      begin
        class_eval do
          attach_function(func, ary.first, ary.last)
        end
      rescue FFI::NotFoundError
        # that's okay
      end
    end

  end
end
